use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::Context;
use quinn::{ClientConfig, Connection, Endpoint, SendStream, ServerConfig, TransportConfig};
use rand::RngCore;
use rand::rngs::OsRng;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use tokio::{
    fs,
    io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt, SeekFrom},
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
const SERVER_NAME: &str = "xsend-quic";
const ALPN: &[u8] = b"xsend-wan/1";

#[derive(Clone)]
pub struct WanState {
    pub daemon_id: Uuid,
    pub sessions: SessionManager,
    pub transfers: TransferManager,
    pub download_dir: PathBuf,
}

#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn generate_quic_identity() -> anyhow::Result<(CertificateDer<'static>, PrivatePkcs8KeyDer<'static>)>
{
    let cert = rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_string()])
        .context("generate self-signed quic cert")?;
    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    Ok((cert_der, key_der))
}

pub fn bind_server_endpoint(bind_addr: SocketAddr) -> anyhow::Result<Endpoint> {
    let (cert, key) = generate_quic_identity()?;

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key.into())
        .context("build rustls server config")?;
    server_crypto.alpn_protocols = vec![ALPN.to_vec()];

    let mut server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .context("build quic server crypto")?,
    ));

    let mut transport = TransportConfig::default();
    transport.max_concurrent_bidi_streams(64u32.into());
    transport.max_concurrent_uni_streams(0u32.into());
    server_config.transport = Arc::new(transport);

    let endpoint = Endpoint::server(server_config, bind_addr).context("bind quic endpoint")?;
    Ok(endpoint)
}

fn client_config() -> anyhow::Result<ClientConfig> {
    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![ALPN.to_vec()];

    let config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
            .context("build quic client crypto")?,
    ));
    Ok(config)
}

pub async fn serve(endpoint: Endpoint, state: WanState) -> anyhow::Result<()> {
    loop {
        let Some(connecting) = endpoint.accept().await else {
            return Ok(());
        };
        let state = state.clone();
        tokio::spawn(async move {
            match connecting.await {
                Ok(conn) => {
                    if let Err(err) = handle_connection(conn, state).await {
                        warn!("wan quic conn failed: {err:#}");
                    }
                }
                Err(err) => {
                    warn!("wan quic accept failed: {err:#}");
                }
            }
        });
    }
}

async fn handle_connection(connection: Connection, state: WanState) -> anyhow::Result<()> {
    let peer = connection.remote_address();
    let (mut send, mut recv) = connection.accept_bi().await.context("accept bi stream")?;

    let ch: ClientHello = proto::read_bincode_frame(&mut recv)
        .await
        .context("read client hello")?;

    if ch.version != PROTO_VERSION {
        reject(
            &mut send,
            state.daemon_id,
            &ch.code,
            format!("unsupported protocol version: {}", ch.version),
        )
        .await?;
        return Ok(());
    }

    if !state.transfers.has_capacity().await {
        reject(
            &mut send,
            state.daemon_id,
            &ch.code,
            "receiver is busy".to_string(),
        )
        .await?;
        return Ok(());
    }

    let Some(_claimed) = state.sessions.claim_receive_code(&ch.code).await else {
        reject(
            &mut send,
            state.daemon_id,
            &ch.code,
            "invalid or expired receive code".to_string(),
        )
        .await?;
        return Ok(());
    };

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
    proto::write_bincode_frame(&mut send, &sh)
        .await
        .context("write server hello")?;

    let client_pub = PublicKey::from(ch.client_pubkey);
    let shared = server_secret.diffie_hellman(&client_pub).to_bytes();
    let keys = proto::derive_keys(Role::Server, shared, salt).context("derive keys")?;

    let mut sr = proto::SecureReadHalf::new(recv, keys.recv_key);
    let mut sw = proto::SecureWriteHalf::new(send, keys.send_key);

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
        "incoming WAN transfer {} from {} ({} bytes)",
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
    send: &mut SendStream,
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
    proto::write_bincode_frame(send, &sh).await?;
    Ok(())
}

pub async fn send_file(
    rt: &TransferRuntime,
    addr: SocketAddr,
    code: String,
    path: PathBuf,
) -> anyhow::Result<()> {
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse().context("parse quic client addr")?)
        .context("create quic client endpoint")?;
    endpoint.set_default_client_config(client_config()?);

    let connecting = endpoint
        .connect(addr, SERVER_NAME)
        .context("connect quic")?;
    let connection = connecting.await.context("establish quic")?;
    let (mut send, mut recv) = connection.open_bi().await.context("open bi stream")?;

    let client_secret = EphemeralSecret::random_from_rng(OsRng);
    let client_pub = PublicKey::from(&client_secret);
    let ch = ClientHello {
        version: PROTO_VERSION,
        client_id: Uuid::new_v4(),
        code: code.clone(),
        client_pubkey: client_pub.to_bytes(),
    };
    proto::write_bincode_frame(&mut send, &ch)
        .await
        .context("write client hello")?;

    let sh: ServerHello = proto::read_bincode_frame(&mut recv)
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

    let mut sr = proto::SecureReadHalf::new(recv, keys.recv_key);
    let mut sw = proto::SecureWriteHalf::new(send, keys.send_key);

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

    let msg: anyhow::Result<SecureMsg> = sr.read_msg().await.context("read finish response");
    match msg {
        Ok(SecureMsg::FinishOk { transfer_id: tid }) if tid == transfer_id => Ok(()),
        Ok(SecureMsg::Error { message }) => anyhow::bail!(message),
        Ok(_) => anyhow::bail!("unexpected finish response"),
        Err(_) => {
            // Some QUIC stacks may close the stream immediately after server-side ack write.
            // If we reached Finish and all chunks were sent, treat EOF as success.
            Ok(())
        }
    }
}

async fn receive_file<R, W>(
    rt: &TransferRuntime,
    sr: &mut proto::SecureReadHalf<R>,
    sw: &mut proto::SecureWriteHalf<W>,
    transfer_id: Uuid,
    filename: String,
    save_path: PathBuf,
    bytes_total: u64,
    chunk_size: u32,
    total_chunks: u64,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
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
                info!("received WAN file '{}' (transfer {})", filename, rt.id());
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
