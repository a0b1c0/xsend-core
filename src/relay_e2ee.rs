use anyhow::{Context, anyhow};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit},
};
use hkdf::Hkdf;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};

pub const RELAY_PLAINTEXT_MAX_BYTES: usize = 10 * 1024 * 1024;
pub const RELAY_TRANSPORT_MAX_BYTES: usize = RELAY_PLAINTEXT_MAX_BYTES + 8192;

const RELAY_FILE_MAGIC: &[u8; 4] = b"XTR1";
const PAIR_KDF_SALT: &[u8] = b"xsend-relay-e2ee-pair-v1";
const PAIR_AEAD_AAD: &[u8] = b"xsend-relay-pair-key";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayFileEnvelope {
    pub filename: String,
    pub content_type: String,
    pub data: Vec<u8>,
}

pub fn encrypt_file_envelope(key32: &[u8; 32], env: &RelayFileEnvelope) -> anyhow::Result<Vec<u8>> {
    let plain = bincode::serialize(env).context("serialize relay envelope")?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key32));
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plain.as_ref())
        .map_err(|_| anyhow!("encrypt relay envelope"))?;

    let mut out = Vec::with_capacity(4 + 12 + ct.len());
    out.extend_from_slice(RELAY_FILE_MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn decrypt_file_envelope(key32: &[u8; 32], blob: &[u8]) -> anyhow::Result<Option<RelayFileEnvelope>> {
    if blob.len() < 4 + 12 || &blob[0..4] != RELAY_FILE_MAGIC {
        return Ok(None);
    }
    let nonce = &blob[4..16];
    let ct = &blob[16..];
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key32));
    let plain = cipher
        .decrypt(Nonce::from_slice(nonce), ct)
        .map_err(|_| anyhow!("decrypt relay envelope"))?;
    let env: RelayFileEnvelope = bincode::deserialize(&plain).context("decode relay envelope")?;
    Ok(Some(env))
}

pub fn b64url_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub fn b64url_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(s.trim().as_bytes())
        .context("invalid base64url")
}

pub fn x25519_public_from_secret(secret32: [u8; 32]) -> [u8; 32] {
    x25519(secret32, X25519_BASEPOINT_BYTES)
}

pub fn x25519_shared(secret32: [u8; 32], peer_public32: [u8; 32]) -> [u8; 32] {
    x25519(secret32, peer_public32)
}

pub fn derive_pair_wrap_key(shared32: [u8; 32]) -> anyhow::Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(PAIR_KDF_SALT), &shared32);
    let mut out = [0u8; 32];
    hk.expand(b"wrap", &mut out)
        .map_err(|_| anyhow!("expand pair wrap key"))?;
    Ok(out)
}

pub fn encrypt_pair_file_key(wrap_key32: &[u8; 32], file_key32: &[u8; 32]) -> anyhow::Result<([u8; 12], Vec<u8>)> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(wrap_key32));
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: file_key32,
                aad: PAIR_AEAD_AAD,
            },
        )
        .map_err(|_| anyhow!("encrypt pair key payload"))?;
    Ok((nonce, ct))
}

pub fn decrypt_pair_file_key(wrap_key32: &[u8; 32], nonce12: &[u8; 12], ciphertext: &[u8]) -> anyhow::Result<[u8; 32]> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(wrap_key32));
    let pt = cipher
        .decrypt(
            Nonce::from_slice(nonce12),
            chacha20poly1305::aead::Payload {
                msg: ciphertext,
                aad: PAIR_AEAD_AAD,
            },
        )
        .map_err(|_| anyhow!("decrypt pair key payload"))?;
    if pt.len() != 32 {
        anyhow::bail!("invalid decrypted key length");
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&pt);
    Ok(out)
}
