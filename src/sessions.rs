use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rand::{Rng, rngs::OsRng};
use serde::Serialize;
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReceiveSessionStatus {
    Pending,
    Claimed,
    Expired,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReceiveSessionView {
    pub id: Uuid,
    pub code: String,
    pub status: ReceiveSessionStatus,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub claimed_at_ms: Option<u64>,
}

#[derive(Clone)]
pub struct SessionManager {
    inner: Arc<Mutex<Inner>>,
    ttl: Duration,
}

#[derive(Debug)]
struct Inner {
    by_id: HashMap<Uuid, ReceiveSession>,
    by_code: HashMap<String, Uuid>,
}

#[derive(Debug, Clone)]
struct ReceiveSession {
    id: Uuid,
    code: String,
    created_at_ms: u64,
    expires_at_ms: u64,
    claimed_at_ms: Option<u64>,
}

impl SessionManager {
    pub fn new(ttl: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                by_id: HashMap::new(),
                by_code: HashMap::new(),
            })),
            ttl,
        }
    }

    pub async fn create_receive_session(&self) -> ReceiveSessionView {
        let mut guard = self.inner.lock().await;
        guard.purge_expired();

        let now = now_ms();
        let expires_at_ms = now.saturating_add(self.ttl.as_millis() as u64);

        let code = loop {
            let c = format!("{:06}", OsRng.gen_range(0..=999_999u32));
            if !guard.by_code.contains_key(&c) {
                break c;
            }
        };

        let id = Uuid::new_v4();
        let s = ReceiveSession {
            id,
            code: code.clone(),
            created_at_ms: now,
            expires_at_ms,
            claimed_at_ms: None,
        };
        guard.by_code.insert(code.clone(), id);
        guard.by_id.insert(id, s.clone());
        s.view()
    }

    pub async fn open_receive_session(&self, code: &str) -> anyhow::Result<ReceiveSessionView> {
        let code = code.trim();
        if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
            anyhow::bail!("invalid code (expected 6 digits)");
        }

        let mut guard = self.inner.lock().await;
        guard.purge_expired();

        // Reset any existing session using this code (claimed or pending).
        if let Some(id) = guard.by_code.get(code).copied() {
            if let Some(s) = guard.by_id.remove(&id) {
                guard.by_code.remove(&s.code);
            }
        }

        let now = now_ms();
        let expires_at_ms = now.saturating_add(self.ttl.as_millis() as u64);
        let id = Uuid::new_v4();
        let s = ReceiveSession {
            id,
            code: code.to_string(),
            created_at_ms: now,
            expires_at_ms,
            claimed_at_ms: None,
        };
        guard.by_code.insert(code.to_string(), id);
        guard.by_id.insert(id, s.clone());
        Ok(s.view())
    }

    pub async fn claim_receive_code(&self, code: &str) -> Option<ReceiveSessionView> {
        let mut guard = self.inner.lock().await;
        guard.purge_expired();

        let id = guard.by_code.get(code).copied()?;
        let now = now_ms();

        // Avoid holding a mutable borrow across map mutations.
        let expired = guard.by_id.get(&id).is_some_and(|s| now >= s.expires_at_ms);
        if expired {
            if let Some(s) = guard.by_id.remove(&id) {
                guard.by_code.remove(&s.code);
            }
            return None;
        }

        let s = guard.by_id.get_mut(&id)?;
        if s.claimed_at_ms.is_some() {
            return None;
        }
        s.claimed_at_ms = Some(now);
        Some(s.clone().view())
    }

    pub async fn list_receive_sessions(&self) -> Vec<ReceiveSessionView> {
        let mut guard = self.inner.lock().await;
        guard.purge_expired();
        guard.by_id.values().cloned().map(|s| s.view()).collect()
    }

    pub async fn get_receive_session_by_code(&self, code: &str) -> Option<ReceiveSessionView> {
        let mut guard = self.inner.lock().await;
        guard.purge_expired();
        let id = guard.by_code.get(code).copied()?;
        guard.by_id.get(&id).cloned().map(|s| s.view())
    }
}

impl Inner {
    fn purge_expired(&mut self) {
        let now = now_ms();
        let mut expired_ids = Vec::new();
        for (id, s) in &self.by_id {
            if now >= s.expires_at_ms {
                expired_ids.push(*id);
            }
        }
        for id in expired_ids {
            if let Some(s) = self.by_id.remove(&id) {
                self.by_code.remove(&s.code);
            }
        }
    }
}

impl ReceiveSession {
    fn view(self) -> ReceiveSessionView {
        let now = now_ms();
        let status = if now >= self.expires_at_ms {
            ReceiveSessionStatus::Expired
        } else if self.claimed_at_ms.is_some() {
            ReceiveSessionStatus::Claimed
        } else {
            ReceiveSessionStatus::Pending
        };
        ReceiveSessionView {
            id: self.id,
            code: self.code,
            status,
            created_at_ms: self.created_at_ms,
            expires_at_ms: self.expires_at_ms,
            claimed_at_ms: self.claimed_at_ms,
        }
    }
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

    #[tokio::test]
    async fn create_and_claim() {
        let mgr = SessionManager::new(Duration::from_secs(60));
        let s = mgr.create_receive_session().await;
        assert_eq!(s.code.len(), 6);
        assert_eq!(s.status, ReceiveSessionStatus::Pending);

        let claimed = mgr.claim_receive_code(&s.code).await.unwrap();
        assert_eq!(claimed.status, ReceiveSessionStatus::Claimed);

        // Cannot claim twice.
        assert!(mgr.claim_receive_code(&s.code).await.is_none());
    }
}
