use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU8, AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use serde::{Deserialize, Serialize};
use tokio::fs;
use tokio::sync::{Mutex, Notify, mpsc};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{lan, wan};

#[derive(Debug, Clone)]
pub struct TransferManagerConfig {
    pub max_running_transfers: usize,
    pub recovery_file: Option<PathBuf>,
}

impl TransferManagerConfig {
    pub fn free_defaults() -> Self {
        Self {
            max_running_transfers: 5,
            recovery_file: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransferDir {
    Send,
    Receive,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransferStatus {
    Queued,
    Running,
    Completed,
    Failed,
    Canceled,
}

impl TransferStatus {
    fn as_u8(self) -> u8 {
        match self {
            TransferStatus::Queued => 0,
            TransferStatus::Running => 1,
            TransferStatus::Completed => 2,
            TransferStatus::Failed => 3,
            TransferStatus::Canceled => 4,
        }
    }

    fn from_u8(v: u8) -> Self {
        match v {
            0 => TransferStatus::Queued,
            1 => TransferStatus::Running,
            2 => TransferStatus::Completed,
            3 => TransferStatus::Failed,
            4 => TransferStatus::Canceled,
            _ => TransferStatus::Failed,
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            TransferStatus::Completed | TransferStatus::Failed | TransferStatus::Canceled
        )
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TransferView {
    pub id: Uuid,
    pub dir: TransferDir,
    pub status: TransferStatus,
    pub created_at_ms: u64,
    pub remote: Option<String>,
    pub filename: Option<String>,
    pub save_path: Option<String>,
    pub bytes_total: u64,
    pub bytes_done: u64,
    pub total_chunks: u64,
    pub chunks_done: u64,
    pub error: Option<String>,
}

#[derive(Debug)]
pub struct TransferRuntime {
    id: Uuid,
    dir: TransferDir,
    created_at_ms: u64,

    status: AtomicU8,
    bytes_total: u64,
    bytes_done: AtomicU64,
    total_chunks: u64,
    chunks_done: AtomicU64,

    remote: Mutex<Option<String>>,
    filename: Mutex<Option<String>>,
    save_path: Mutex<Option<String>>,
    error: Mutex<Option<String>>,

    cancel: CancellationToken,
    status_notify: Notify,
}

impl TransferRuntime {
    fn new(id: Uuid, dir: TransferDir, bytes_total: u64, total_chunks: u64) -> Self {
        Self {
            id,
            dir,
            created_at_ms: now_ms(),
            status: AtomicU8::new(TransferStatus::Queued.as_u8()),
            bytes_total,
            bytes_done: AtomicU64::new(0),
            total_chunks,
            chunks_done: AtomicU64::new(0),
            remote: Mutex::new(None),
            filename: Mutex::new(None),
            save_path: Mutex::new(None),
            error: Mutex::new(None),
            cancel: CancellationToken::new(),
            status_notify: Notify::new(),
        }
    }

    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn dir(&self) -> TransferDir {
        self.dir
    }

    pub fn status(&self) -> TransferStatus {
        TransferStatus::from_u8(self.status.load(Ordering::Acquire))
    }

    pub(crate) fn set_status(&self, status: TransferStatus) {
        self.status.store(status.as_u8(), Ordering::Release);
        self.status_notify.notify_waiters();
    }

    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    pub fn request_cancel(&self) {
        self.cancel.cancel();
        self.set_status(TransferStatus::Canceled);
    }

    pub fn set_progress(&self, bytes_done: u64, chunks_done: u64) {
        self.bytes_done.store(bytes_done, Ordering::Release);
        self.chunks_done.store(chunks_done, Ordering::Release);
    }

    pub fn add_progress(&self, bytes_delta: u64, chunks_delta: u64) {
        self.bytes_done.fetch_add(bytes_delta, Ordering::Release);
        self.chunks_done.fetch_add(chunks_delta, Ordering::Release);
    }

    pub async fn set_remote(&self, remote: String) {
        *self.remote.lock().await = Some(remote);
    }

    pub async fn set_filename(&self, filename: String) {
        *self.filename.lock().await = Some(filename);
    }

    pub async fn set_save_path(&self, path: String) {
        *self.save_path.lock().await = Some(path);
    }

    pub async fn fail(&self, err: anyhow::Error) {
        *self.error.lock().await = Some(err.to_string());
        self.set_status(TransferStatus::Failed);
    }

    pub async fn view(&self) -> TransferView {
        let (remote, filename, save_path, error) = {
            let remote = self.remote.lock().await.clone();
            let filename = self.filename.lock().await.clone();
            let save_path = self.save_path.lock().await.clone();
            let error = self.error.lock().await.clone();
            (remote, filename, save_path, error)
        };

        TransferView {
            id: self.id,
            dir: self.dir,
            status: self.status(),
            created_at_ms: self.created_at_ms,
            remote,
            filename,
            save_path,
            bytes_total: self.bytes_total,
            bytes_done: self.bytes_done.load(Ordering::Acquire),
            total_chunks: self.total_chunks,
            chunks_done: self.chunks_done.load(Ordering::Acquire),
            error,
        }
    }
}

#[derive(Debug)]
struct SendParams {
    addr: SocketAddr,
    code: String,
    path: PathBuf,
}

#[derive(Debug)]
struct SendAutoParams {
    candidates: Vec<AutoRouteCandidate>,
    code: String,
    path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct AutoRouteCandidate {
    pub lan_addr: SocketAddr,
    pub wan_addr: Option<SocketAddr>,
}

#[derive(Debug)]
struct SendWanParams {
    addr: SocketAddr,
    code: String,
    path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RecoveryFile {
    version: u8,
    tasks: Vec<RecoveryTask>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RecoveryTask {
    kind: RecoveryKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum RecoveryKind {
    Send {
        addr: String,
        code: String,
        path: String,
    },
    SendAuto {
        candidates: Vec<RecoveryAutoRouteCandidate>,
        code: String,
        path: String,
    },
    SendWan {
        addr: String,
        code: String,
        path: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RecoveryAutoRouteCandidate {
    lan_addr: String,
    wan_addr: Option<String>,
}

#[derive(Debug)]
enum TransferKind {
    Send(SendParams),
    SendAuto(SendAutoParams),
    SendWan(SendWanParams),
    Receive,
}

#[derive(Debug)]
struct TransferOutcome {
    id: Uuid,
}

#[derive(Clone)]
pub struct TransferManager {
    inner: Arc<Mutex<Inner>>,
    tx_outcome: mpsc::Sender<TransferOutcome>,
}

#[derive(Debug)]
struct Inner {
    cfg: TransferManagerConfig,
    transfers: HashMap<Uuid, Arc<TransferRuntime>>,
    kinds: HashMap<Uuid, TransferKind>,
    queue: VecDeque<Uuid>,
    running: HashSet<Uuid>,
}

impl TransferManager {
    pub fn new(cfg: TransferManagerConfig) -> Self {
        let inner = Arc::new(Mutex::new(Inner {
            cfg,
            transfers: HashMap::new(),
            kinds: HashMap::new(),
            queue: VecDeque::new(),
            running: HashSet::new(),
        }));

        let (tx_outcome, mut rx_outcome) = mpsc::channel::<TransferOutcome>(128);
        let inner_bg = Arc::clone(&inner);
        let tx_bg = tx_outcome.clone();
        tokio::spawn(async move {
            while let Some(outcome) = rx_outcome.recv().await {
                let mut guard = inner_bg.lock().await;
                guard.running.remove(&outcome.id);
                guard.maybe_start(&tx_bg);
                let snapshot = guard.recovery_snapshot();
                drop(guard);
                if let Some((path, file)) = snapshot {
                    if let Err(err) = write_recovery_file(&path, &file).await {
                        tracing::warn!("persist transfer recovery state failed: {err:#}");
                    }
                }
            }
        });

        Self { inner, tx_outcome }
    }

    pub async fn recover_from_disk(&self) -> anyhow::Result<usize> {
        let recovery_path = {
            let guard = self.inner.lock().await;
            guard.cfg.recovery_file.clone()
        };
        let Some(path) = recovery_path else {
            return Ok(0);
        };

        let Some(file) = read_recovery_file(&path).await? else {
            return Ok(0);
        };

        let mut restored = 0usize;
        for task in file.tasks {
            match task.kind {
                RecoveryKind::Send { addr, code, path } => {
                    let parsed_addr = match addr.parse::<SocketAddr>() {
                        Ok(v) => v,
                        Err(_) => {
                            tracing::warn!("skip recovered send task: invalid addr {addr}");
                            continue;
                        }
                    };
                    match self
                        .create_send(parsed_addr, code, PathBuf::from(path.clone()))
                        .await
                    {
                        Ok(id) => {
                            tracing::info!("recovered send transfer {id}");
                            restored += 1;
                        }
                        Err(err) => {
                            tracing::warn!("skip recovered send task ({path}): {err}");
                        }
                    }
                }
                RecoveryKind::SendAuto {
                    candidates,
                    code,
                    path,
                } => {
                    let mut parsed = Vec::new();
                    for c in candidates {
                        let lan_addr = match c.lan_addr.parse::<SocketAddr>() {
                            Ok(v) => v,
                            Err(_) => continue,
                        };
                        let wan_addr = c
                            .wan_addr
                            .as_deref()
                            .and_then(|s| s.parse::<SocketAddr>().ok());
                        parsed.push(AutoRouteCandidate { lan_addr, wan_addr });
                    }
                    if parsed.is_empty() {
                        tracing::warn!(
                            "skip recovered auto-route task: no valid candidates for {path}"
                        );
                        continue;
                    }
                    match self
                        .create_send_auto(parsed, code, PathBuf::from(path.clone()))
                        .await
                    {
                        Ok(id) => {
                            tracing::info!("recovered auto-route transfer {id}");
                            restored += 1;
                        }
                        Err(err) => {
                            tracing::warn!("skip recovered auto-route task ({path}): {err}");
                        }
                    }
                }
                RecoveryKind::SendWan { addr, code, path } => {
                    let parsed_addr = match addr.parse::<SocketAddr>() {
                        Ok(v) => v,
                        Err(_) => {
                            tracing::warn!("skip recovered wan task: invalid addr {addr}");
                            continue;
                        }
                    };
                    match self
                        .create_send_wan(parsed_addr, code, PathBuf::from(path.clone()))
                        .await
                    {
                        Ok(id) => {
                            tracing::info!("recovered wan transfer {id}");
                            restored += 1;
                        }
                        Err(err) => {
                            tracing::warn!("skip recovered wan task ({path}): {err}");
                        }
                    }
                }
            }
        }

        // Ensure file is rewritten without stale entries even if some tasks were dropped.
        self.persist_recovery().await;
        Ok(restored)
    }

    pub async fn has_capacity(&self) -> bool {
        let guard = self.inner.lock().await;
        guard.running.len() < guard.cfg.max_running_transfers
    }

    pub async fn list(&self) -> Vec<TransferView> {
        let transfers = {
            let guard = self.inner.lock().await;
            guard.transfers.values().cloned().collect::<Vec<_>>()
        };

        let mut out = Vec::with_capacity(transfers.len());
        for t in transfers {
            out.push(t.view().await);
        }
        out.sort_by_key(|v| v.created_at_ms);
        out
    }

    pub async fn get(&self, id: Uuid) -> Option<TransferView> {
        let t = {
            let guard = self.inner.lock().await;
            guard.transfers.get(&id).cloned()
        }?;
        Some(t.view().await)
    }

    pub async fn create_send(
        &self,
        addr: SocketAddr,
        code: String,
        path: PathBuf,
    ) -> anyhow::Result<Uuid> {
        let meta = tokio::fs::metadata(&path)
            .await
            .with_context(|| "read file metadata")?;
        if !meta.is_file() {
            anyhow::bail!("path is not a regular file");
        }
        let bytes_total = meta.len();
        let chunk_size = lan::default_chunk_size();
        let total_chunks = bytes_total.div_ceil(chunk_size as u64);

        let id = Uuid::new_v4();
        let rt = Arc::new(TransferRuntime::new(
            id,
            TransferDir::Send,
            bytes_total,
            total_chunks,
        ));
        rt.set_remote(addr.to_string()).await;
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            rt.set_filename(name.to_string()).await;
        }

        let params = SendParams { addr, code, path };

        let mut guard = self.inner.lock().await;
        guard.transfers.insert(id, Arc::clone(&rt));
        guard.kinds.insert(id, TransferKind::Send(params));
        guard.queue.push_back(id);
        guard.maybe_start(&self.tx_outcome);
        drop(guard);
        self.persist_recovery().await;
        Ok(id)
    }

    pub async fn create_send_auto(
        &self,
        candidates: Vec<AutoRouteCandidate>,
        code: String,
        path: PathBuf,
    ) -> anyhow::Result<Uuid> {
        if candidates.is_empty() {
            anyhow::bail!("no candidates");
        }

        let meta = tokio::fs::metadata(&path)
            .await
            .with_context(|| "read file metadata")?;
        if !meta.is_file() {
            anyhow::bail!("path is not a regular file");
        }
        let bytes_total = meta.len();
        let chunk_size = lan::default_chunk_size();
        let total_chunks = bytes_total.div_ceil(chunk_size as u64);

        let id = Uuid::new_v4();
        let rt = Arc::new(TransferRuntime::new(
            id,
            TransferDir::Send,
            bytes_total,
            total_chunks,
        ));
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            rt.set_filename(name.to_string()).await;
        }
        if let Some(first) = candidates.first() {
            rt.set_remote(format!("lan {}", first.lan_addr)).await;
        }

        let params = SendAutoParams {
            candidates,
            code,
            path,
        };

        let mut guard = self.inner.lock().await;
        guard.transfers.insert(id, Arc::clone(&rt));
        guard.kinds.insert(id, TransferKind::SendAuto(params));
        guard.queue.push_back(id);
        guard.maybe_start(&self.tx_outcome);
        drop(guard);
        self.persist_recovery().await;
        Ok(id)
    }

    pub async fn create_send_wan(
        &self,
        addr: SocketAddr,
        code: String,
        path: PathBuf,
    ) -> anyhow::Result<Uuid> {
        let meta = tokio::fs::metadata(&path)
            .await
            .with_context(|| "read file metadata")?;
        if !meta.is_file() {
            anyhow::bail!("path is not a regular file");
        }
        let bytes_total = meta.len();
        let chunk_size = lan::default_chunk_size();
        let total_chunks = bytes_total.div_ceil(chunk_size as u64);

        let id = Uuid::new_v4();
        let rt = Arc::new(TransferRuntime::new(
            id,
            TransferDir::Send,
            bytes_total,
            total_chunks,
        ));
        rt.set_remote(addr.to_string()).await;
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            rt.set_filename(name.to_string()).await;
        }

        let params = SendWanParams { addr, code, path };

        let mut guard = self.inner.lock().await;
        guard.transfers.insert(id, Arc::clone(&rt));
        guard.kinds.insert(id, TransferKind::SendWan(params));
        guard.queue.push_back(id);
        guard.maybe_start(&self.tx_outcome);
        drop(guard);
        self.persist_recovery().await;
        Ok(id)
    }

    pub async fn register_incoming_receive(
        &self,
        peer: SocketAddr,
        filename: String,
        save_path: String,
        bytes_total: u64,
        total_chunks: u64,
    ) -> anyhow::Result<Arc<TransferRuntime>> {
        let id = Uuid::new_v4();
        let rt = Arc::new(TransferRuntime::new(
            id,
            TransferDir::Receive,
            bytes_total,
            total_chunks,
        ));
        rt.set_status(TransferStatus::Running);
        rt.set_remote(peer.to_string()).await;
        rt.set_filename(filename).await;
        rt.set_save_path(save_path).await;

        let mut guard = self.inner.lock().await;
        if guard.running.len() >= guard.cfg.max_running_transfers {
            anyhow::bail!("transfer capacity exceeded");
        }
        guard.running.insert(id);
        guard.transfers.insert(id, Arc::clone(&rt));
        guard.kinds.insert(id, TransferKind::Receive);
        Ok(rt)
    }

    pub async fn cancel(&self, id: Uuid) -> anyhow::Result<()> {
        let (rt, was_running) = {
            let mut guard = self.inner.lock().await;
            let rt = guard
                .transfers
                .get(&id)
                .cloned()
                .context("transfer not found")?;
            let was_running = guard.running.contains(&id);

            // If queued, drop from queue and mark canceled.
            if !was_running {
                guard.queue.retain(|tid| *tid != id);
            }
            (rt, was_running)
        };

        rt.request_cancel();
        if !was_running {
            let _ = self.tx_outcome.send(TransferOutcome { id }).await;
        }
        self.persist_recovery().await;
        Ok(())
    }

    pub async fn notify_finished(&self, id: Uuid) {
        let _ = self.tx_outcome.send(TransferOutcome { id }).await;
    }

    pub async fn wait_terminal_status(&self, id: Uuid) -> Option<TransferStatus> {
        loop {
            let rt = {
                let guard = self.inner.lock().await;
                guard.transfers.get(&id).cloned()
            }?;
            let status = rt.status();
            if status.is_terminal() {
                return Some(status);
            }
            rt.status_notify.notified().await;
        }
    }

    async fn persist_recovery(&self) {
        let snapshot = {
            let guard = self.inner.lock().await;
            guard.recovery_snapshot()
        };
        if let Some((path, file)) = snapshot {
            if let Err(err) = write_recovery_file(&path, &file).await {
                tracing::warn!("persist transfer recovery state failed: {err:#}");
            }
        }
    }
}

impl Inner {
    fn maybe_start(&mut self, tx_outcome: &mpsc::Sender<TransferOutcome>) {
        while self.running.len() < self.cfg.max_running_transfers {
            let Some(id) = self.queue.pop_front() else {
                return;
            };
            let Some(rt) = self.transfers.get(&id).cloned() else {
                continue;
            };
            let Some(kind) = self.kinds.get(&id) else {
                continue;
            };

            if rt.status() != TransferStatus::Queued {
                continue;
            }

            self.running.insert(id);
            rt.set_status(TransferStatus::Running);

            let tx = tx_outcome.clone();

            match kind {
                TransferKind::Receive => continue,
                TransferKind::Send(params) => {
                    let params = SendParams {
                        addr: params.addr,
                        code: params.code.clone(),
                        path: params.path.clone(),
                    };
                    tokio::spawn(async move {
                        let res =
                            lan::send_file(rt.as_ref(), params.addr, params.code, params.path)
                                .await;
                        match res {
                            Ok(()) => rt.set_status(TransferStatus::Completed),
                            Err(err) => {
                                if rt.cancel_token().is_cancelled()
                                    || rt.status() == TransferStatus::Canceled
                                {
                                    rt.set_status(TransferStatus::Canceled);
                                } else {
                                    rt.fail(err).await;
                                }
                            }
                        }
                        let _ = tx.send(TransferOutcome { id }).await;
                    });
                }
                TransferKind::SendAuto(params) => {
                    let candidates = params.candidates.clone();
                    let code = params.code.clone();
                    let path = params.path.clone();
                    tokio::spawn(async move {
                        let cancel = rt.cancel_token();
                        let mut last_err: Option<anyhow::Error> = None;
                        let mut attempts: Vec<String> = Vec::new();

                        let mut lan_addrs: Vec<SocketAddr> = Vec::new();
                        let mut seen_lan = HashSet::new();
                        for c in &candidates {
                            if seen_lan.insert(c.lan_addr) {
                                lan_addrs.push(c.lan_addr);
                            }
                        }

                        let mut wan_addrs: Vec<SocketAddr> = Vec::new();
                        let mut seen_wan = HashSet::new();
                        for c in &candidates {
                            if let Some(addr) = c.wan_addr {
                                if seen_wan.insert(addr) {
                                    wan_addrs.push(addr);
                                }
                            }
                        }

                        // Route policy: LAN first, then WAN.
                        for addr in lan_addrs {
                            if cancel.is_cancelled() || rt.status() == TransferStatus::Canceled {
                                rt.set_status(TransferStatus::Canceled);
                                let _ = tx.send(TransferOutcome { id }).await;
                                return;
                            }

                            rt.set_remote(format!("lan {}", addr)).await;
                            attempts.push(format!("lan:{addr}"));
                            match lan::send_file(rt.as_ref(), addr, code.clone(), path.clone()).await
                            {
                                Ok(()) => {
                                    rt.set_status(TransferStatus::Completed);
                                    let _ = tx.send(TransferOutcome { id }).await;
                                    return;
                                }
                                Err(err) => {
                                    last_err = Some(err);
                                }
                            }
                        }

                        for addr in wan_addrs {
                            if cancel.is_cancelled() || rt.status() == TransferStatus::Canceled {
                                rt.set_status(TransferStatus::Canceled);
                                let _ = tx.send(TransferOutcome { id }).await;
                                return;
                            }

                            rt.set_remote(format!("wan {}", addr)).await;
                            attempts.push(format!("wan:{addr}"));
                            match wan::send_file(rt.as_ref(), addr, code.clone(), path.clone()).await
                            {
                                Ok(()) => {
                                    rt.set_status(TransferStatus::Completed);
                                    let _ = tx.send(TransferOutcome { id }).await;
                                    return;
                                }
                                Err(err) => {
                                    last_err = Some(err);
                                }
                            }
                        }

                        if cancel.is_cancelled() || rt.status() == TransferStatus::Canceled {
                            rt.set_status(TransferStatus::Canceled);
                        } else if let Some(err) = last_err {
                            rt.fail(anyhow::anyhow!(
                                "all routes failed ({}); last error: {}",
                                attempts.join(", "),
                                err
                            ))
                            .await;
                        } else {
                            rt.fail(anyhow::anyhow!("no route candidate available")).await;
                        }

                        let _ = tx.send(TransferOutcome { id }).await;
                    });
                }
                TransferKind::SendWan(params) => {
                    let params = SendWanParams {
                        addr: params.addr,
                        code: params.code.clone(),
                        path: params.path.clone(),
                    };
                    tokio::spawn(async move {
                        let res =
                            wan::send_file(rt.as_ref(), params.addr, params.code, params.path)
                                .await;
                        match res {
                            Ok(()) => rt.set_status(TransferStatus::Completed),
                            Err(err) => {
                                if rt.cancel_token().is_cancelled()
                                    || rt.status() == TransferStatus::Canceled
                                {
                                    rt.set_status(TransferStatus::Canceled);
                                } else {
                                    rt.fail(err).await;
                                }
                            }
                        }
                        let _ = tx.send(TransferOutcome { id }).await;
                    });
                }
            }
        }
    }

    fn recovery_snapshot(&self) -> Option<(PathBuf, RecoveryFile)> {
        let path = self.cfg.recovery_file.clone()?;
        let mut tasks = Vec::new();

        for (id, kind) in &self.kinds {
            let Some(rt) = self.transfers.get(id) else {
                continue;
            };
            let status = rt.status();
            if status.is_terminal() || rt.dir() != TransferDir::Send {
                continue;
            }

            let kind = match kind {
                TransferKind::Send(p) => RecoveryKind::Send {
                    addr: p.addr.to_string(),
                    code: p.code.clone(),
                    path: p.path.to_string_lossy().to_string(),
                },
                TransferKind::SendAuto(p) => {
                    let candidates = p
                        .candidates
                        .iter()
                        .map(|c| RecoveryAutoRouteCandidate {
                            lan_addr: c.lan_addr.to_string(),
                            wan_addr: c.wan_addr.map(|v| v.to_string()),
                        })
                        .collect::<Vec<_>>();
                    RecoveryKind::SendAuto {
                        candidates,
                        code: p.code.clone(),
                        path: p.path.to_string_lossy().to_string(),
                    }
                }
                TransferKind::SendWan(p) => RecoveryKind::SendWan {
                    addr: p.addr.to_string(),
                    code: p.code.clone(),
                    path: p.path.to_string_lossy().to_string(),
                },
                TransferKind::Receive => continue,
            };

            tasks.push(RecoveryTask { kind });
        }

        Some((path, RecoveryFile { version: 1, tasks }))
    }
}

async fn read_recovery_file(path: &PathBuf) -> anyhow::Result<Option<RecoveryFile>> {
    let bytes = match fs::read(path).await {
        Ok(v) => v,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).context("read transfer recovery file"),
    };
    if bytes.is_empty() {
        return Ok(None);
    }
    let parsed = serde_json::from_slice::<RecoveryFile>(&bytes)
        .context("parse transfer recovery file json")?;
    if parsed.version != 1 {
        tracing::warn!(
            "unsupported transfer recovery version {}; ignoring {}",
            parsed.version,
            path.display()
        );
        return Ok(None);
    }
    Ok(Some(parsed))
}

async fn write_recovery_file(path: &PathBuf, file: &RecoveryFile) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("create transfer recovery dir {}", parent.display()))?;
    }
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(file).context("serialize transfer recovery file")?;
    fs::write(&tmp, bytes)
        .await
        .with_context(|| format!("write transfer recovery temp {}", tmp.display()))?;
    fs::rename(&tmp, path)
        .await
        .with_context(|| format!("rename transfer recovery file {}", path.display()))?;
    Ok(())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn persists_and_recovers_queued_send_task() {
        let tmp = tempdir().expect("tempdir");
        let data_path = tmp.path().join("a.txt");
        fs::write(&data_path, b"hello").await.expect("write file");
        let recovery_path = tmp.path().join("transfers_recovery.json");

        let cfg = TransferManagerConfig {
            max_running_transfers: 0,
            recovery_file: Some(recovery_path.clone()),
        };

        let mgr = TransferManager::new(cfg.clone());
        let addr: SocketAddr = "127.0.0.1:65000".parse().expect("addr");
        let _ = mgr
            .create_send(addr, "123456".to_string(), data_path.clone())
            .await
            .expect("create send");

        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        let raw = fs::read_to_string(&recovery_path)
            .await
            .expect("read recovery");
        assert!(raw.contains("\"send\""));
        drop(mgr);

        let mgr2 = TransferManager::new(cfg);
        let restored = mgr2.recover_from_disk().await.expect("recover");
        assert_eq!(restored, 1);
        let list = mgr2.list().await;
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].status, TransferStatus::Queued);
    }
}
