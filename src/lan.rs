use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::Context;
use rand::RngCore;
use rand::rngs::OsRng;
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, SeekFrom},
    net::{TcpListener, TcpStream},
};
use tracing::{info, warn};
use uuid::Uuid;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::{
    proto::{self, ClientHello, PROTO_VERSION, Role, SecureMsg, ServerHello},
    sessions::SessionManager,
    transfers::{TransferManager, TransferRuntime, TransferStatus},
};

const DEFAULT_CHUNK_SIZE: usize = 2 * 1024 * 1024;

pub fn default_chunk_size() -> usize {
    DEFAULT_CHUNK_SIZE
}

#[derive(Clone)]
pub struct LanState {
    pub daemon_id: Uuid,
    pub sessions: SessionManager,
    pub transfers: TransferManager,
    pub download_dir: PathBuf,
}

pub async fn serve(listener: TcpListener, state: LanState) -> anyhow::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await.context("accept lan conn")?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_incoming(stream, peer, state).await {
                warn!("lan conn from {peer} failed: {err:#}");
            }
        });
    }
}

async fn handle_incoming(
    mut stream: TcpStream,
    peer: SocketAddr,
    state: LanState,
) -> anyhow::Result<()> {
    let ch: ClientHello = proto::read_bincode_frame(&mut stream)
        .await
        .context("read client hello")?;

    if ch.version != PROTO_VERSION {
        reject(
            &mut stream,
            state.daemon_id,
            &ch.code,
            format!("unsupported protocol version: {}", ch.version),
        )
        .await?;
        return Ok(());
    }

    if !state.transfers.has_capacity().await {
        reject(
            &mut stream,
            state.daemon_id,
            &ch.code,
            "receiver is busy".to_string(),
        )
        .await?;
        return Ok(());
    }

    let Some(_claimed) = state.sessions.claim_receive_code(&ch.code).await else {
        reject(
            &mut stream,
            state.daemon_id,
            &ch.code,
            "invalid or expired receive code".to_string(),
        )
        .await?;
        return Ok(());
    };

    // Handshake: ephemeral X25519 + HKDF salt from server.
    let server_secret = EphemeralSecret::random_from_rng(OsRng);
    let server_pub = PublicKey::from(&server_secret);
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);

    let sh = ServerHello {
        version: PROTO_VERSION,
        server_id: state.daemon_id,
        accept: true,
        reason: None,
        code: ch.code.clone(),
        server_pubkey: server_pub.to_bytes(),
        salt,
    };
    proto::write_bincode_frame(&mut stream, &sh)
        .await
        .context("write server hello")?;

    let client_pub = PublicKey::from(ch.client_pubkey);
    let shared = server_secret.diffie_hellman(&client_pub).to_bytes();
    let keys = proto::derive_keys(Role::Server, shared, salt).context("derive keys")?;

    let (read_half, write_half) = stream.into_split();
    let mut sr = proto::SecureReadHalf::new(read_half, keys.recv_key);
    let mut sw = proto::SecureWriteHalf::new(write_half, keys.send_key);

    let msg: SecureMsg = sr.read_msg().await.context("read confirm")?;
    match msg {
        SecureMsg::Confirm { code } if code == ch.code => {}
        SecureMsg::Confirm { .. } => {
            sw.write_msg(&SecureMsg::Error {
                message: "code mismatch".to_string(),
            })
            .await?;
            return Ok(());
        }
        _ => {
            sw.write_msg(&SecureMsg::Error {
                message: "expected confirm".to_string(),
            })
            .await?;
            return Ok(());
        }
    }
    sw.write_msg(&SecureMsg::ConfirmOk).await?;

    let offer: SecureMsg = sr.read_msg().await.context("read offer")?;
    let (transfer_id, filename, bytes_total, chunk_size, total_chunks) = match offer {
        SecureMsg::SendOffer {
            transfer_id,
            filename,
            bytes_total,
            chunk_size,
            total_chunks,
        } => (transfer_id, filename, bytes_total, chunk_size, total_chunks),
        _ => {
            sw.write_msg(&SecureMsg::Error {
                message: "expected send offer".to_string(),
            })
            .await?;
            return Ok(());
        }
    };

    let safe_name = sanitize_filename(&filename);
    let save_path = allocate_download_path(&state.download_dir, &safe_name)
        .await
        .context("allocate download path")?;

    let rt = state
        .transfers
        .register_incoming_receive(
            peer,
            safe_name.clone(),
            save_path.to_string_lossy().to_string(),
            bytes_total,
            total_chunks,
        )
        .await
        .context("register incoming transfer")?;

    info!(
        "incoming transfer {} from {} ({} bytes)",
        rt.id(),
        peer,
        bytes_total
    );

    if let Err(err) = receive_file(
        &rt,
        &mut sr,
        &mut sw,
        transfer_id,
        safe_name,
        save_path,
        bytes_total,
        chunk_size,
        total_chunks,
    )
    .await
    {
        if rt.status() != TransferStatus::Canceled {
            rt.fail(err).await;
        }
    }

    state.transfers.notify_finished(rt.id()).await;
    Ok(())
}

async fn reject(
    stream: &mut TcpStream,
    daemon_id: Uuid,
    code: &str,
    reason: String,
) -> anyhow::Result<()> {
    let sh = ServerHello {
        version: PROTO_VERSION,
        server_id: daemon_id,
        accept: false,
        reason: Some(reason),
        code: code.to_string(),
        server_pubkey: [0u8; 32],
        salt: [0u8; 32],
    };
    proto::write_bincode_frame(stream, &sh).await?;
    Ok(())
}

pub async fn send_file(
    rt: &TransferRuntime,
    addr: SocketAddr,
    code: String,
    path: PathBuf,
) -> anyhow::Result<()> {
    let mut stream = TcpStream::connect(addr)
        .await
        .with_context(|| format!("connect to {addr}"))?;

    let client_secret = EphemeralSecret::random_from_rng(OsRng);
    let client_pub = PublicKey::from(&client_secret);
    let ch = ClientHello {
        version: PROTO_VERSION,
        client_id: Uuid::new_v4(),
        code: code.clone(),
        client_pubkey: client_pub.to_bytes(),
    };
    proto::write_bincode_frame(&mut stream, &ch)
        .await
        .context("write client hello")?;

    let sh: ServerHello = proto::read_bincode_frame(&mut stream)
        .await
        .context("read server hello")?;
    if sh.version != PROTO_VERSION {
        anyhow::bail!("unsupported protocol version: {}", sh.version);
    }
    if !sh.accept {
        anyhow::bail!(sh.reason.unwrap_or_else(|| "rejected".to_string()));
    }
    if sh.code != code {
        anyhow::bail!("pairing code mismatch");
    }

    let server_pub = PublicKey::from(sh.server_pubkey);
    let shared = client_secret.diffie_hellman(&server_pub).to_bytes();
    let keys = proto::derive_keys(Role::Client, shared, sh.salt).context("derive keys")?;

    let (read_half, write_half) = stream.into_split();
    let mut sr = proto::SecureReadHalf::new(read_half, keys.recv_key);
    let mut sw = proto::SecureWriteHalf::new(write_half, keys.send_key);

    sw.write_msg(&SecureMsg::Confirm { code: code.clone() })
        .await
        .context("write confirm")?;
    let msg: SecureMsg = sr.read_msg().await.context("read confirm ok")?;
    match msg {
        SecureMsg::ConfirmOk => {}
        SecureMsg::Error { message } => anyhow::bail!(message),
        _ => anyhow::bail!("unexpected confirm response"),
    }

    let meta = fs::metadata(&path)
        .await
        .with_context(|| "read file metadata")?;
    if !meta.is_file() {
        anyhow::bail!("path is not a regular file");
    }

    let bytes_total = meta.len();
    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file.bin")
        .to_string();
    let chunk_size = DEFAULT_CHUNK_SIZE as u32;
    let total_chunks = bytes_total.div_ceil(DEFAULT_CHUNK_SIZE as u64);
    let transfer_id = Uuid::new_v4();

    sw.write_msg(&SecureMsg::SendOffer {
        transfer_id,
        filename: filename.clone(),
        bytes_total,
        chunk_size,
        total_chunks,
    })
    .await
    .context("write offer")?;

    let msg: SecureMsg = sr.read_msg().await.context("read accept")?;
    let resume_bitmap = match msg {
        SecureMsg::SendAccept {
            transfer_id: tid,
            resume_bitmap,
        } if tid == transfer_id => resume_bitmap,
        SecureMsg::Error { message } => anyhow::bail!(message),
        _ => anyhow::bail!("unexpected accept response"),
    };

    let bitmap_len = (usize::try_from(total_chunks).context("chunk count overflow")? + 7) / 8;
    if resume_bitmap.len() != bitmap_len {
        anyhow::bail!("invalid resume bitmap");
    }

    let cancel = rt.cancel_token();

    let mut file = fs::File::open(&path).await.context("open file")?;
    let mut hasher = blake3::Hasher::new();

    let mut bytes_sent = 0u64;
    let mut chunks_sent = 0u64;

    for idx in 0..total_chunks {
        if cancel.is_cancelled() {
            anyhow::bail!("canceled");
        }

        let remaining = bytes_total.saturating_sub(idx * DEFAULT_CHUNK_SIZE as u64);
        let len = (DEFAULT_CHUNK_SIZE as u64).min(remaining) as usize;
        let mut data = vec![0u8; len];
        file.read_exact(&mut data).await.context("read chunk")?;
        hasher.update(&data);

        if bitmap_has(&resume_bitmap, idx) {
            continue;
        }

        let chunk_hash = blake3::hash(&data);
        sw.write_msg(&SecureMsg::Chunk {
            transfer_id,
            idx,
            hash_blake3: *chunk_hash.as_bytes(),
            data,
        })
        .await
        .with_context(|| format!("send chunk {idx}"))?;

        bytes_sent = bytes_sent.saturating_add(len as u64);
        chunks_sent = chunks_sent.saturating_add(1);
        rt.set_progress(bytes_sent, chunks_sent);
    }

    let file_hash = hasher.finalize();
    sw.write_msg(&SecureMsg::Finish {
        transfer_id,
        file_hash_blake3: *file_hash.as_bytes(),
    })
    .await
    .context("send finish")?;

    let msg: SecureMsg = sr.read_msg().await.context("read finish response")?;
    match msg {
        SecureMsg::FinishOk { transfer_id: tid } if tid == transfer_id => Ok(()),
        SecureMsg::Error { message } => anyhow::bail!(message),
        _ => anyhow::bail!("unexpected finish response"),
    }
}

async fn receive_file(
    rt: &TransferRuntime,
    sr: &mut proto::SecureReadHalf<tokio::net::tcp::OwnedReadHalf>,
    sw: &mut proto::SecureWriteHalf<tokio::net::tcp::OwnedWriteHalf>,
    transfer_id: Uuid,
    filename: String,
    save_path: PathBuf,
    bytes_total: u64,
    chunk_size: u32,
    total_chunks: u64,
) -> anyhow::Result<()> {
    if chunk_size as usize != DEFAULT_CHUNK_SIZE {
        sw.write_msg(&SecureMsg::Error {
            message: "unsupported chunk size".to_string(),
        })
        .await?;
        anyhow::bail!("unsupported chunk size");
    }

    fs::create_dir_all(&save_path.parent().unwrap_or(Path::new(".")))
        .await
        .context("create download dir")?;

    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .read(true)
        .open(&save_path)
        .await
        .context("open destination file")?;
    file.set_len(bytes_total).await.context("set file len")?;

    let bitmap_len = (usize::try_from(total_chunks).context("chunk count overflow")? + 7) / 8;
    let mut bitmap = vec![0u8; bitmap_len];

    rt.set_save_path(save_path.to_string_lossy().to_string())
        .await;

    sw.write_msg(&SecureMsg::SendAccept {
        transfer_id,
        resume_bitmap: bitmap.clone(),
    })
    .await
    .context("send accept")?;

    let cancel = rt.cancel_token();

    let mut bytes_done = 0u64;
    let mut chunks_done = 0u64;

    loop {
        if cancel.is_cancelled() {
            sw.write_msg(&SecureMsg::Error {
                message: "canceled".to_string(),
            })
            .await?;
            rt.set_status(TransferStatus::Canceled);
            anyhow::bail!("canceled");
        }

        let msg: SecureMsg = sr.read_msg().await.context("read secure msg")?;
        match msg {
            SecureMsg::Chunk {
                transfer_id: tid,
                idx,
                hash_blake3,
                data,
            } if tid == transfer_id => {
                if idx >= total_chunks {
                    sw.write_msg(&SecureMsg::Error {
                        message: "chunk index out of range".to_string(),
                    })
                    .await?;
                    anyhow::bail!("chunk index out of range");
                }

                let remaining = bytes_total.saturating_sub(idx * DEFAULT_CHUNK_SIZE as u64);
                let expected_len = (DEFAULT_CHUNK_SIZE as u64).min(remaining) as usize;
                if data.len() != expected_len {
                    sw.write_msg(&SecureMsg::Error {
                        message: "invalid chunk length".to_string(),
                    })
                    .await?;
                    anyhow::bail!("invalid chunk length");
                }

                if bitmap_has(&bitmap, idx) {
                    continue;
                }

                let h = blake3::hash(&data);
                if h.as_bytes() != &hash_blake3 {
                    sw.write_msg(&SecureMsg::Error {
                        message: "chunk hash mismatch".to_string(),
                    })
                    .await?;
                    anyhow::bail!("chunk hash mismatch");
                }

                let offset = idx
                    .checked_mul(DEFAULT_CHUNK_SIZE as u64)
                    .context("chunk offset overflow")?;
                file.seek(SeekFrom::Start(offset))
                    .await
                    .context("seek dest")?;
                file.write_all(&data).await.context("write dest")?;

                bitmap_set(&mut bitmap, idx)?;
                bytes_done = bytes_done.saturating_add(data.len() as u64);
                chunks_done = chunks_done.saturating_add(1);
                rt.set_progress(bytes_done, chunks_done);

                if chunks_done == total_chunks {
                    // Wait for Finish.
                }
            }
            SecureMsg::Finish {
                transfer_id: tid,
                file_hash_blake3,
            } if tid == transfer_id => {
                if chunks_done != total_chunks {
                    sw.write_msg(&SecureMsg::Error {
                        message: format!("missing chunks: {}/{}", chunks_done, total_chunks),
                    })
                    .await?;
                    anyhow::bail!("missing chunks");
                }

                let computed = blake3_file(&save_path, cancel.clone())
                    .await
                    .context("compute file hash")?;
                if computed != file_hash_blake3 {
                    sw.write_msg(&SecureMsg::Error {
                        message: "file hash mismatch".to_string(),
                    })
                    .await?;
                    anyhow::bail!("file hash mismatch");
                }

                sw.write_msg(&SecureMsg::FinishOk { transfer_id })
                    .await
                    .context("send finish ok")?;
                rt.set_status(TransferStatus::Completed);
                info!("received file '{}' (transfer {})", filename, rt.id());
                return Ok(());
            }
            SecureMsg::Error { message } => {
                anyhow::bail!("peer error: {message}");
            }
            _ => {
                sw.write_msg(&SecureMsg::Error {
                    message: "unexpected message".to_string(),
                })
                .await?;
                anyhow::bail!("unexpected message");
            }
        }
    }
}

fn bitmap_has(bits: &[u8], idx: u64) -> bool {
    let idx_usize = match usize::try_from(idx) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let byte_idx = idx_usize / 8;
    let bit = idx_usize % 8;
    let Some(b) = bits.get(byte_idx) else {
        return false;
    };
    (b & (1u8 << bit)) != 0
}

fn bitmap_set(bits: &mut [u8], idx: u64) -> anyhow::Result<()> {
    let idx_usize = usize::try_from(idx).context("chunk index overflow")?;
    let byte_idx = idx_usize / 8;
    let bit = idx_usize % 8;
    let Some(b) = bits.get_mut(byte_idx) else {
        anyhow::bail!("bitmap overflow");
    };
    *b |= 1u8 << bit;
    Ok(())
}

async fn blake3_file(
    path: &Path,
    cancel: tokio_util::sync::CancellationToken,
) -> anyhow::Result<[u8; 32]> {
    let mut file = fs::File::open(path).await.context("open file")?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        if cancel.is_cancelled() {
            anyhow::bail!("canceled");
        }
        let n = file.read(&mut buf).await.context("read")?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(*hasher.finalize().as_bytes())
}

fn sanitize_filename(name: &str) -> String {
    let base = Path::new(name)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("file.bin");
    let mut out = String::with_capacity(base.len());
    for ch in base.chars() {
        let ok = ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_' | ' ');
        out.push(if ok { ch } else { '_' });
    }
    let out = out.trim().to_string();
    if out.is_empty() {
        "file.bin".to_string()
    } else {
        out
    }
}

async fn allocate_download_path(dir: &Path, filename: &str) -> anyhow::Result<PathBuf> {
    fs::create_dir_all(dir)
        .await
        .context("create download dir")?;

    let mut candidate = dir.join(filename);
    if fs::try_exists(&candidate).await.unwrap_or(false) {
        let stem = Path::new(filename)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("file");
        let ext = Path::new(filename).extension().and_then(|s| s.to_str());
        for i in 1..=999u32 {
            let name = match ext {
                Some(ext) => format!("{stem}-{i}.{ext}"),
                None => format!("{stem}-{i}"),
            };
            candidate = dir.join(name);
            if !fs::try_exists(&candidate).await.unwrap_or(false) {
                break;
            }
        }
    }
    Ok(candidate)
}
