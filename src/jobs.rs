use std::{
    collections::{HashMap, VecDeque},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use serde::Serialize;
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncSeekExt, SeekFrom},
    sync::{Mutex, Notify, mpsc},
    task::JoinSet,
    time::Duration,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const DEFAULT_CHUNK_SIZE: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct JobManagerConfig {
    pub max_running_jobs: usize,
    pub global_stream_limit: usize,
    pub default_streams_lan: usize,
    pub default_streams_wan: usize,
    pub chunk_size: usize,
    pub per_chunk_delay_ms: u64,
}

impl JobManagerConfig {
    pub fn free_defaults() -> Self {
        Self {
            max_running_jobs: 5,
            global_stream_limit: 16,
            default_streams_lan: 4,
            default_streams_wan: 2,
            chunk_size: DEFAULT_CHUNK_SIZE,
            per_chunk_delay_ms: 0,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Network {
    Lan,
    Wan,
}

impl Network {
    fn default_streams(self, cfg: &JobManagerConfig) -> usize {
        match self {
            Network::Lan => cfg.default_streams_lan,
            Network::Wan => cfg.default_streams_wan,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Queued,
    Running,
    Paused,
    Completed,
    Failed,
    Canceled,
}

impl JobStatus {
    fn as_u8(self) -> u8 {
        match self {
            JobStatus::Queued => 0,
            JobStatus::Running => 1,
            JobStatus::Paused => 2,
            JobStatus::Completed => 3,
            JobStatus::Failed => 4,
            JobStatus::Canceled => 5,
        }
    }

    fn from_u8(v: u8) -> Self {
        match v {
            0 => JobStatus::Queued,
            1 => JobStatus::Running,
            2 => JobStatus::Paused,
            3 => JobStatus::Completed,
            4 => JobStatus::Failed,
            5 => JobStatus::Canceled,
            _ => JobStatus::Failed,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct JobView {
    pub id: Uuid,
    pub status: JobStatus,
    pub path: String,
    pub created_at_ms: u64,
    pub bytes_total: u64,
    pub bytes_done: u64,
    pub total_chunks: u64,
    pub chunks_done: u64,
    pub desired_streams: usize,
    pub allocated_streams: usize,
    pub file_hash_blake3_hex: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct JobManagerStats {
    pub running_jobs: usize,
    pub queued_jobs: usize,
    pub running_streams: usize,
    pub max_running_jobs: usize,
    pub global_stream_limit: usize,
}

#[derive(Clone)]
pub struct JobManager {
    inner: Arc<Mutex<JobManagerInner>>,
    tx_outcome: mpsc::Sender<JobOutcome>,
}

#[derive(Debug)]
struct JobManagerInner {
    cfg: JobManagerConfig,
    jobs: HashMap<Uuid, Arc<JobRuntime>>,
    queue: VecDeque<Uuid>,
    running: HashMap<Uuid, usize>,
    running_streams: usize,
}

#[derive(Debug)]
struct JobOutcome {
    id: Uuid,
    // runtime already stores the failure reason; this is used for scheduling/unblocking.
    _ok: bool,
}

impl JobManager {
    pub fn new(cfg: JobManagerConfig) -> Self {
        let inner = Arc::new(Mutex::new(JobManagerInner {
            cfg,
            jobs: HashMap::new(),
            queue: VecDeque::new(),
            running: HashMap::new(),
            running_streams: 0,
        }));

        let (tx_outcome, mut rx_outcome) = mpsc::channel::<JobOutcome>(128);
        let inner_bg = Arc::clone(&inner);
        let tx_bg = tx_outcome.clone();
        tokio::spawn(async move {
            while let Some(outcome) = rx_outcome.recv().await {
                let mut guard = inner_bg.lock().await;
                if let Some(streams) = guard.running.remove(&outcome.id) {
                    guard.running_streams = guard.running_streams.saturating_sub(streams);
                }
                guard.maybe_start_jobs(&tx_bg);
            }
        });

        Self { inner, tx_outcome }
    }

    pub async fn stats(&self) -> JobManagerStats {
        let guard = self.inner.lock().await;
        JobManagerStats {
            running_jobs: guard.running.len(),
            queued_jobs: guard.queue.len(),
            running_streams: guard.running_streams,
            max_running_jobs: guard.cfg.max_running_jobs,
            global_stream_limit: guard.cfg.global_stream_limit,
        }
    }

    pub async fn list_jobs(&self) -> Vec<JobView> {
        let jobs: Vec<Arc<JobRuntime>> = {
            let guard = self.inner.lock().await;
            guard.jobs.values().cloned().collect()
        };

        let mut views = Vec::with_capacity(jobs.len());
        for job in jobs {
            views.push(job.view().await);
        }
        views.sort_by_key(|v| v.created_at_ms);
        views
    }

    pub async fn get_job(&self, id: Uuid) -> Option<JobView> {
        let job = {
            let guard = self.inner.lock().await;
            guard.jobs.get(&id).cloned()
        }?;
        Some(job.view().await)
    }

    pub async fn create_hash_file_job(
        &self,
        path: PathBuf,
        network: Network,
    ) -> anyhow::Result<Uuid> {
        let meta = fs::metadata(&path)
            .await
            .with_context(|| "read file metadata")?;
        if !meta.is_file() {
            anyhow::bail!("path is not a regular file");
        }

        let bytes_total = meta.len();
        let created_at_ms = now_ms();

        let (chunk_size, total_chunks, bitmap_len, hashes_len, per_chunk_delay_ms, desired_streams) = {
            let guard = self.inner.lock().await;
            let chunk_size = guard.cfg.chunk_size;
            let total_chunks = bytes_total.div_ceil(chunk_size as u64);
            let bitmap_len = usize::try_from(total_chunks)
                .context("chunk count overflow")?
                .div_ceil(8);
            let hashes_len = usize::try_from(total_chunks)
                .context("chunk count overflow")?
                .checked_mul(32)
                .context("chunk hashes allocation overflow")?;
            (
                chunk_size,
                total_chunks,
                bitmap_len,
                hashes_len,
                guard.cfg.per_chunk_delay_ms,
                network.default_streams(&guard.cfg),
            )
        };

        let id = Uuid::new_v4();
        let job = Arc::new(JobRuntime::new_hash_file(
            id,
            created_at_ms,
            path,
            bytes_total,
            chunk_size,
            total_chunks,
            desired_streams,
            bitmap_len,
            hashes_len,
            per_chunk_delay_ms,
        ));

        let mut guard = self.inner.lock().await;
        guard.jobs.insert(id, job);
        guard.queue.push_back(id);
        guard.maybe_start_jobs(&self.tx_outcome);
        Ok(id)
    }

    pub async fn pause(&self, id: Uuid) -> anyhow::Result<()> {
        let job = {
            let guard = self.inner.lock().await;
            guard.jobs.get(&id).cloned()
        }
        .context("job not found")?;

        // If queued, remove from scheduling queue so it won't be dropped/started.
        if job.allocated_streams() == 0 && job.status() == JobStatus::Queued {
            let mut guard = self.inner.lock().await;
            guard.queue.retain(|jid| *jid != id);
        }
        job.pause().await
    }

    pub async fn resume(&self, id: Uuid) -> anyhow::Result<()> {
        let job = {
            let guard = self.inner.lock().await;
            guard.jobs.get(&id).cloned()
        }
        .context("job not found")?;

        // If it never started, put it back into the queue and schedule.
        if job.allocated_streams() == 0 && job.status() == JobStatus::Paused {
            let mut guard = self.inner.lock().await;
            guard.queue.push_back(id);
            job.set_status(JobStatus::Queued);
            guard.maybe_start_jobs(&self.tx_outcome);
            return Ok(());
        }

        job.resume().await
    }

    pub async fn cancel(&self, id: Uuid) -> anyhow::Result<()> {
        let job = {
            let guard = self.inner.lock().await;
            guard.jobs.get(&id).cloned()
        }
        .context("job not found")?;

        // If queued (not started), cancel immediately and remove from queue.
        if job.allocated_streams() == 0
            && matches!(job.status(), JobStatus::Queued | JobStatus::Paused)
        {
            let mut guard = self.inner.lock().await;
            guard.queue.retain(|jid| *jid != id);
            job.cancel_queued();
            return Ok(());
        }

        job.cancel().await
    }
}

impl JobManagerInner {
    fn maybe_start_jobs(&mut self, tx_outcome: &mpsc::Sender<JobOutcome>) {
        loop {
            if self.running.len() >= self.cfg.max_running_jobs {
                break;
            }
            let Some(id) = self.queue.pop_front() else {
                break;
            };
            let Some(job) = self.jobs.get(&id).cloned() else {
                continue;
            };
            if job.status() != JobStatus::Queued {
                continue;
            }

            let available_streams = self
                .cfg
                .global_stream_limit
                .saturating_sub(self.running_streams);
            if available_streams == 0 {
                self.queue.push_front(id);
                break;
            }

            let allocated = job.desired_streams().min(available_streams).max(1);
            self.running.insert(id, allocated);
            self.running_streams += allocated;
            job.start(allocated, tx_outcome.clone());
        }
    }
}

#[derive(Debug)]
struct HashFileData {
    bitmap: Vec<u8>,
    chunk_hashes: Vec<u8>,
    file_hash_blake3_hex: Option<String>,
}

#[derive(Debug)]
pub struct JobRuntime {
    id: Uuid,
    created_at_ms: u64,
    path: PathBuf,
    bytes_total: u64,
    chunk_size: usize,
    total_chunks: u64,
    desired_streams: usize,
    per_chunk_delay_ms: u64,

    status: AtomicU8,
    allocated_streams: AtomicUsize,

    bytes_done: AtomicU64,
    chunks_done: AtomicU64,

    paused: AtomicBool,
    pause_notify: Notify,
    cancel: CancellationToken,
    user_cancel_requested: AtomicBool,

    error: Mutex<Option<String>>,
    data: Mutex<HashFileData>,
}

impl JobRuntime {
    fn new_hash_file(
        id: Uuid,
        created_at_ms: u64,
        path: PathBuf,
        bytes_total: u64,
        chunk_size: usize,
        total_chunks: u64,
        desired_streams: usize,
        bitmap_len: usize,
        hashes_len: usize,
        per_chunk_delay_ms: u64,
    ) -> Self {
        Self {
            id,
            created_at_ms,
            path,
            bytes_total,
            chunk_size,
            total_chunks,
            desired_streams,
            per_chunk_delay_ms,
            status: AtomicU8::new(JobStatus::Queued.as_u8()),
            allocated_streams: AtomicUsize::new(0),
            bytes_done: AtomicU64::new(0),
            chunks_done: AtomicU64::new(0),
            paused: AtomicBool::new(false),
            pause_notify: Notify::new(),
            cancel: CancellationToken::new(),
            user_cancel_requested: AtomicBool::new(false),
            error: Mutex::new(None),
            data: Mutex::new(HashFileData {
                bitmap: vec![0u8; bitmap_len],
                chunk_hashes: vec![0u8; hashes_len],
                file_hash_blake3_hex: None,
            }),
        }
    }

    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn status(&self) -> JobStatus {
        JobStatus::from_u8(self.status.load(Ordering::Acquire))
    }

    fn set_status(&self, s: JobStatus) {
        self.status.store(s.as_u8(), Ordering::Release);
    }

    fn allocated_streams(&self) -> usize {
        self.allocated_streams.load(Ordering::Acquire)
    }

    fn desired_streams(&self) -> usize {
        self.desired_streams
    }

    fn start(self: &Arc<Self>, allocated: usize, tx_outcome: mpsc::Sender<JobOutcome>) {
        self.allocated_streams.store(allocated, Ordering::Release);
        self.paused.store(false, Ordering::Release);
        self.set_status(JobStatus::Running);

        let job = Arc::clone(self);
        tokio::spawn(async move {
            job.run_hash_file(allocated, tx_outcome).await;
        });
    }

    pub async fn pause(&self) -> anyhow::Result<()> {
        match self.status() {
            JobStatus::Queued => {
                self.paused.store(true, Ordering::Release);
                self.set_status(JobStatus::Paused);
                Ok(())
            }
            JobStatus::Running => {
                self.paused.store(true, Ordering::Release);
                self.set_status(JobStatus::Paused);
                Ok(())
            }
            JobStatus::Paused => Ok(()),
            JobStatus::Completed | JobStatus::Failed | JobStatus::Canceled => {
                anyhow::bail!("job is not pausable")
            }
        }
    }

    pub async fn resume(&self) -> anyhow::Result<()> {
        match self.status() {
            JobStatus::Paused => {
                self.paused.store(false, Ordering::Release);
                self.set_status(JobStatus::Running);
                self.pause_notify.notify_waiters();
                Ok(())
            }
            JobStatus::Running => Ok(()),
            JobStatus::Queued => Ok(()),
            JobStatus::Completed | JobStatus::Failed | JobStatus::Canceled => {
                anyhow::bail!("job is not resumable")
            }
        }
    }

    pub async fn cancel(&self) -> anyhow::Result<()> {
        match self.status() {
            JobStatus::Completed | JobStatus::Failed | JobStatus::Canceled => {
                anyhow::bail!("job is not cancelable")
            }
            _ => {
                self.user_cancel_requested.store(true, Ordering::Release);
                self.cancel.cancel();
                self.pause_notify.notify_waiters();
                self.set_status(JobStatus::Canceled);
                Ok(())
            }
        }
    }

    fn cancel_queued(&self) {
        self.user_cancel_requested.store(true, Ordering::Release);
        self.cancel.cancel();
        self.set_status(JobStatus::Canceled);
    }

    pub async fn view(&self) -> JobView {
        let status = self.status();
        let bytes_done = self.bytes_done.load(Ordering::Acquire);
        let chunks_done = self.chunks_done.load(Ordering::Acquire);

        let (file_hash, err) = {
            let data = self.data.lock().await;
            let error = self.error.lock().await;
            (data.file_hash_blake3_hex.clone(), error.clone())
        };

        JobView {
            id: self.id,
            status,
            path: self.path.to_string_lossy().to_string(),
            created_at_ms: self.created_at_ms,
            bytes_total: self.bytes_total,
            bytes_done,
            total_chunks: self.total_chunks,
            chunks_done,
            desired_streams: self.desired_streams,
            allocated_streams: self.allocated_streams(),
            file_hash_blake3_hex: file_hash,
            error: err,
        }
    }

    async fn run_hash_file(self: Arc<Self>, streams: usize, tx_outcome: mpsc::Sender<JobOutcome>) {
        let next_chunk = Arc::new(AtomicU64::new(0));

        let mut joins = JoinSet::new();
        for _ in 0..streams {
            let job = Arc::clone(&self);
            let next = Arc::clone(&next_chunk);
            joins.spawn(async move { job.hash_worker(next).await });
        }

        let mut ok = true;
        while let Some(res) = joins.join_next().await {
            match res {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    ok = false;
                    let mut e = self.error.lock().await;
                    *e = Some(err.to_string());
                    self.cancel.cancel();
                }
                Err(join_err) => {
                    ok = false;
                    let mut e = self.error.lock().await;
                    *e = Some(format!("worker panicked: {join_err}"));
                    self.cancel.cancel();
                }
            }
        }

        if self.cancel.is_cancelled() && self.user_cancel_requested.load(Ordering::Acquire) {
            self.set_status(JobStatus::Canceled);
            let _ = tx_outcome
                .send(JobOutcome {
                    id: self.id,
                    _ok: false,
                })
                .await;
            return;
        }

        if !ok {
            self.set_status(JobStatus::Failed);
            let _ = tx_outcome
                .send(JobOutcome {
                    id: self.id,
                    _ok: false,
                })
                .await;
            return;
        }

        match self.compute_file_hash().await {
            Ok(hash_hex) => {
                let mut data = self.data.lock().await;
                data.file_hash_blake3_hex = Some(hash_hex);
                self.set_status(JobStatus::Completed);
                let _ = tx_outcome
                    .send(JobOutcome {
                        id: self.id,
                        _ok: true,
                    })
                    .await;
            }
            Err(err) => {
                if self.cancel.is_cancelled() && self.user_cancel_requested.load(Ordering::Acquire)
                {
                    self.set_status(JobStatus::Canceled);
                    let _ = tx_outcome
                        .send(JobOutcome {
                            id: self.id,
                            _ok: false,
                        })
                        .await;
                    return;
                }

                let mut e = self.error.lock().await;
                *e = Some(err.to_string());
                self.set_status(JobStatus::Failed);
                let _ = tx_outcome
                    .send(JobOutcome {
                        id: self.id,
                        _ok: false,
                    })
                    .await;
            }
        }
    }

    async fn hash_worker(self: Arc<Self>, next_chunk: Arc<AtomicU64>) -> anyhow::Result<()> {
        let mut file = fs::File::open(&self.path)
            .await
            .with_context(|| "open file")?;

        loop {
            if self.cancel.is_cancelled() {
                return Ok(());
            }

            while self.paused.load(Ordering::Acquire) {
                self.pause_notify.notified().await;
                if self.cancel.is_cancelled() {
                    return Ok(());
                }
            }

            let idx = next_chunk.fetch_add(1, Ordering::AcqRel);
            if idx >= self.total_chunks {
                break;
            }

            let offset = idx
                .checked_mul(self.chunk_size as u64)
                .context("chunk offset overflow")?;
            let remaining = self.bytes_total.saturating_sub(offset);
            let len = (self.chunk_size as u64).min(remaining) as usize;

            file.seek(SeekFrom::Start(offset))
                .await
                .with_context(|| "seek")?;
            let mut buf = vec![0u8; len];
            file.read_exact(&mut buf).await.with_context(|| "read")?;

            let hash = blake3::hash(&buf);
            {
                let mut data = self.data.lock().await;
                bitmap_set(&mut data.bitmap, idx)?;
                let start = usize::try_from(idx).context("chunk index overflow")? * 32;
                data.chunk_hashes[start..start + 32].copy_from_slice(hash.as_bytes());
            }

            self.bytes_done.fetch_add(len as u64, Ordering::Release);
            self.chunks_done.fetch_add(1, Ordering::Release);

            if self.per_chunk_delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(self.per_chunk_delay_ms)).await;
            }
        }

        Ok(())
    }

    async fn compute_file_hash(&self) -> anyhow::Result<String> {
        let mut file = fs::File::open(&self.path)
            .await
            .with_context(|| "open file for hash")?;
        let mut hasher = blake3::Hasher::new();
        let mut buf = vec![0u8; 1024 * 1024];
        loop {
            if self.cancel.is_cancelled() {
                anyhow::bail!("canceled");
            }
            let n = file.read(&mut buf).await.with_context(|| "read")?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(hex::encode(hasher.finalize().as_bytes()))
    }
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

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use tokio::time::Instant;

    fn write_sized_file(bytes: usize) -> NamedTempFile {
        let mut f = NamedTempFile::new().expect("tmp file");
        let data = vec![0u8; 1024 * 1024];
        let mut remaining = bytes;
        while remaining > 0 {
            let n = remaining.min(data.len());
            std::io::Write::write_all(&mut f, &data[..n]).expect("write");
            remaining -= n;
        }
        f
    }

    #[tokio::test]
    async fn respects_max_running_jobs_queueing() {
        let cfg = JobManagerConfig {
            max_running_jobs: 1,
            global_stream_limit: 1,
            default_streams_lan: 1,
            default_streams_wan: 1,
            chunk_size: 1024 * 1024,
            per_chunk_delay_ms: 50,
        };
        let mgr = JobManager::new(cfg);

        let f1 = write_sized_file(5 * 1024 * 1024);
        let f2 = write_sized_file(5 * 1024 * 1024);

        let id1 = mgr
            .create_hash_file_job(f1.path().to_path_buf(), Network::Lan)
            .await
            .unwrap();
        let id2 = mgr
            .create_hash_file_job(f2.path().to_path_buf(), Network::Lan)
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(20)).await;
        let j1 = mgr.get_job(id1).await.unwrap();
        let j2 = mgr.get_job(id2).await.unwrap();
        assert!(matches!(
            j1.status,
            JobStatus::Running | JobStatus::Completed
        ));
        assert!(matches!(
            j2.status,
            JobStatus::Queued | JobStatus::Running | JobStatus::Completed
        ));

        // Wait until both complete; max_running_jobs=1 should serialize.
        let start = Instant::now();
        loop {
            let j1 = mgr.get_job(id1).await.unwrap();
            let j2 = mgr.get_job(id2).await.unwrap();
            if j1.status == JobStatus::Completed && j2.status == JobStatus::Completed {
                break;
            }
            if start.elapsed() > Duration::from_secs(10) {
                panic!("timeout waiting for jobs");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}
