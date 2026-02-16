use std::io;

use anyhow::Context;
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit},
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::Sha256;
use uuid::Uuid;

pub const PROTO_VERSION: u16 = 1;
pub const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientHello {
    pub version: u16,
    pub client_id: Uuid,
    pub code: String,
    pub client_pubkey: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerHello {
    pub version: u16,
    pub server_id: Uuid,
    pub accept: bool,
    pub reason: Option<String>,
    pub code: String,
    pub server_pubkey: [u8; 32],
    pub salt: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecureMsg {
    Confirm {
        code: String,
    },
    ConfirmOk,

    SendOffer {
        transfer_id: Uuid,
        filename: String,
        bytes_total: u64,
        chunk_size: u32,
        total_chunks: u64,
    },
    SendAccept {
        transfer_id: Uuid,
        resume_bitmap: Vec<u8>,
    },

    Chunk {
        transfer_id: Uuid,
        idx: u64,
        hash_blake3: [u8; 32],
        data: Vec<u8>,
    },

    Finish {
        transfer_id: Uuid,
        file_hash_blake3: [u8; 32],
    },
    FinishOk {
        transfer_id: Uuid,
    },

    Error {
        message: String,
    },
}

#[derive(Debug, Clone, Copy)]
pub enum Role {
    Client,
    Server,
}

#[derive(Debug, Clone)]
pub struct DerivedKeys {
    pub send_key: [u8; 32],
    pub recv_key: [u8; 32],
}

pub fn derive_keys(
    role: Role,
    shared_secret: [u8; 32],
    salt: [u8; 32],
) -> anyhow::Result<DerivedKeys> {
    let hk = Hkdf::<Sha256>::new(Some(&salt), &shared_secret);

    let mut key_c2s = [0u8; 32];
    hk.expand(b"xsend v1 key c2s", &mut key_c2s)
        .expect("hkdf expand");
    let mut key_s2c = [0u8; 32];
    hk.expand(b"xsend v1 key s2c", &mut key_s2c)
        .expect("hkdf expand");

    Ok(match role {
        Role::Client => DerivedKeys {
            send_key: key_c2s,
            recv_key: key_s2c,
        },
        Role::Server => DerivedKeys {
            send_key: key_s2c,
            recv_key: key_c2s,
        },
    })
}

pub async fn write_frame<W: tokio::io::AsyncWrite + Unpin>(
    w: &mut W,
    data: &[u8],
) -> io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let len: u32 = data
        .len()
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame too large"))?;
    w.write_u32(len).await?;
    w.write_all(data).await?;
    Ok(())
}

pub async fn read_frame<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> io::Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let len = r.read_u32().await? as usize;
    if len > MAX_FRAME_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

pub async fn write_bincode_frame<W: tokio::io::AsyncWrite + Unpin, T: Serialize>(
    w: &mut W,
    msg: &T,
) -> anyhow::Result<()> {
    let bytes = bincode::serialize(msg).context("bincode serialize")?;
    write_frame(w, &bytes).await.context("write frame")?;
    Ok(())
}

pub async fn read_bincode_frame<R: tokio::io::AsyncRead + Unpin, T: DeserializeOwned>(
    r: &mut R,
) -> anyhow::Result<T> {
    let bytes = read_frame(r).await.context("read frame")?;
    let msg = bincode::deserialize(&bytes).context("bincode deserialize")?;
    Ok(msg)
}

pub struct SecureWriteHalf<W> {
    w: W,
    seq: u64,
    cipher: ChaCha20Poly1305,
}

pub struct SecureReadHalf<R> {
    r: R,
    seq: u64,
    cipher: ChaCha20Poly1305,
}

impl<W: tokio::io::AsyncWrite + Unpin> SecureWriteHalf<W> {
    pub fn new(w: W, key: [u8; 32]) -> Self {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        Self { w, seq: 0, cipher }
    }

    pub async fn write_msg<T: Serialize>(&mut self, msg: &T) -> anyhow::Result<()> {
        let pt = bincode::serialize(msg).context("bincode serialize secure msg")?;
        let nonce_bytes = nonce_from_seq(self.seq);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = self
            .cipher
            .encrypt(nonce, pt.as_ref())
            .map_err(|_| anyhow::anyhow!("aead encrypt"))?;
        advance_seq(&mut self.seq)?;
        write_frame(&mut self.w, &ct)
            .await
            .context("write secure frame")?;
        Ok(())
    }
}

impl<R: tokio::io::AsyncRead + Unpin> SecureReadHalf<R> {
    pub fn new(r: R, key: [u8; 32]) -> Self {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        Self { r, seq: 0, cipher }
    }

    pub async fn read_msg<T: DeserializeOwned>(&mut self) -> anyhow::Result<T> {
        let ct = read_frame(&mut self.r).await.context("read secure frame")?;
        let nonce_bytes = nonce_from_seq(self.seq);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let pt = self
            .cipher
            .decrypt(nonce, ct.as_ref())
            .map_err(|_| anyhow::anyhow!("aead decrypt"))?;
        advance_seq(&mut self.seq)?;
        let msg = bincode::deserialize(&pt).context("bincode deserialize secure msg")?;
        Ok(msg)
    }
}

fn advance_seq(seq: &mut u64) -> anyhow::Result<()> {
    if *seq == u64::MAX {
        anyhow::bail!("secure nonce exhausted");
    }
    *seq += 1;
    Ok(())
}

fn nonce_from_seq(seq: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    // 96-bit nonce: 32-bit fixed prefix + 64-bit counter.
    n[4..].copy_from_slice(&seq.to_be_bytes());
    n
}

#[cfg(test)]
mod tests {
    use super::advance_seq;

    #[test]
    fn advance_seq_stops_at_max() {
        let mut seq = u64::MAX - 1;
        advance_seq(&mut seq).expect("advance to max");
        assert_eq!(seq, u64::MAX);
        assert!(advance_seq(&mut seq).is_err());
    }
}
