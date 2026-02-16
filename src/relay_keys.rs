use std::{collections::HashMap, path::PathBuf, sync::Arc};

use anyhow::Context;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

#[derive(Debug, Serialize, Deserialize)]
struct RelayKeysFile {
    version: u32,
    channels: HashMap<String, String>,
}

#[derive(Clone)]
pub struct RelayKeyStore {
    path: PathBuf,
    inner: Arc<Mutex<HashMap<String, [u8; 32]>>>,
}

#[derive(Clone)]
pub struct RelayPairPendingStore {
    inner: Arc<Mutex<HashMap<String, PendingPair>>>,
}

#[derive(Clone)]
struct PendingPair {
    secret32: [u8; 32],
    expires_at_ms: u64,
}

impl RelayKeyStore {
    pub async fn open(path: PathBuf) -> anyhow::Result<Self> {
        let map = load_map(&path).await?;
        Ok(Self {
            path,
            inner: Arc::new(Mutex::new(map)),
        })
    }

    pub async fn get(&self, code: &str) -> Option<[u8; 32]> {
        let key = sanitize_code(code)?;
        let guard = self.inner.lock().await;
        guard.get(key).copied()
    }

    pub async fn get_or_create(&self, code: &str) -> anyhow::Result<[u8; 32]> {
        let key = sanitize_code(code).context("invalid relay code")?.to_string();
        let mut guard = self.inner.lock().await;
        if let Some(v) = guard.get(&key).copied() {
            return Ok(v);
        }

        let mut v = [0u8; 32];
        OsRng.fill_bytes(&mut v);
        guard.insert(key, v);
        persist_map(&self.path, &guard).await?;
        Ok(v)
    }

    pub async fn set(&self, code: &str, value: [u8; 32]) -> anyhow::Result<()> {
        let key = sanitize_code(code).context("invalid relay code")?.to_string();
        let mut guard = self.inner.lock().await;
        guard.insert(key, value);
        persist_map(&self.path, &guard).await
    }
}

impl Default for RelayPairPendingStore {
    fn default() -> Self {
        Self::new()
    }
}

impl RelayPairPendingStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn insert(&self, code: &str, secret32: [u8; 32], expires_at_ms: u64) -> anyhow::Result<()> {
        let key = sanitize_code(code).context("invalid pair code")?.to_string();
        let mut guard = self.inner.lock().await;
        guard.insert(
            key,
            PendingPair {
                secret32,
                expires_at_ms,
            },
        );
        Ok(())
    }

    pub async fn get_valid(&self, code: &str) -> Option<[u8; 32]> {
        let key = sanitize_code(code)?;
        let now = now_ms();
        let mut guard = self.inner.lock().await;
        guard.retain(|_, v| v.expires_at_ms > now);
        guard.get(key).map(|v| v.secret32)
    }

    pub async fn remove(&self, code: &str) {
        if let Some(key) = sanitize_code(code) {
            let mut guard = self.inner.lock().await;
            guard.remove(key);
        }
    }
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    ms as u64
}

fn sanitize_code(code: &str) -> Option<&str> {
    let s = code.trim();
    if s.len() == 6 && s.chars().all(|c| c.is_ascii_digit()) {
        Some(s)
    } else {
        None
    }
}

async fn load_map(path: &PathBuf) -> anyhow::Result<HashMap<String, [u8; 32]>> {
    let data = match tokio::fs::read(path).await {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(e) => return Err(e).context("read relay key file"),
    };

    let parsed: RelayKeysFile = serde_json::from_slice(&data).context("parse relay key file json")?;
    let mut out = HashMap::new();
    for (code, hexv) in parsed.channels {
        if sanitize_code(&code).is_none() {
            continue;
        }
        let bytes = match hex::decode(hexv) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if bytes.len() != 32 {
            continue;
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        out.insert(code, key);
    }
    Ok(out)
}

async fn persist_map(path: &PathBuf, map: &HashMap<String, [u8; 32]>) -> anyhow::Result<()> {
    let channels = map
        .iter()
        .map(|(k, v)| (k.clone(), hex::encode(v)))
        .collect::<HashMap<_, _>>();
    let file = RelayKeysFile {
        version: 1,
        channels,
    };
    let data = serde_json::to_vec_pretty(&file).context("encode relay key file json")?;
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .context("create relay key file dir")?;
    }
    tokio::fs::write(path, data)
        .await
        .context("write relay key file")?;
    Ok(())
}
