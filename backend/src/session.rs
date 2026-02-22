use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::RwLock;
use uuid::Uuid;

pub const SESSION_COOKIE_NAME: &str = "mlist_sid";

#[derive(Debug, Clone)]
pub struct SessionData {
    pub scopes: BTreeSet<String>,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionView {
    pub scopes: Vec<String>,
    #[serde(rename = "expiresAt")]
    pub expires_at: String,
}

#[derive(Debug, Clone)]
pub struct SessionStore {
    inner: Arc<RwLock<HashMap<String, SessionData>>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn get_valid(&self, sid: &str, now: u64) -> Option<SessionData> {
        let mut sessions = self.inner.write().await;
        match sessions.get(sid) {
            Some(session) if session.expires_at > now => Some(session.clone()),
            Some(_) => {
                sessions.remove(sid);
                None
            }
            None => None,
        }
    }

    pub async fn create_or_update(
        &self,
        current_sid: Option<&str>,
        scope: &str,
        ttl_seconds: u64,
        now: u64,
    ) -> (String, SessionData) {
        let mut sessions = self.inner.write().await;

        sessions.retain(|_, session| session.expires_at > now);

        let session_id = match current_sid {
            Some(value) if sessions.contains_key(value) => value.to_string(),
            _ => Uuid::new_v4().simple().to_string(),
        };

        let expires_at = now.saturating_add(ttl_seconds);
        let session = sessions.entry(session_id.clone()).or_insert(SessionData {
            scopes: BTreeSet::new(),
            expires_at,
        });

        session.scopes.insert(scope.to_string());
        session.expires_at = expires_at;

        (session_id, session.clone())
    }

    pub async fn remove(&self, sid: &str) {
        let mut sessions = self.inner.write().await;
        sessions.remove(sid);
    }
}

#[derive(Debug, Clone)]
pub struct LoginRateLimiter {
    inner: Arc<RwLock<HashMap<String, LoginAttempt>>>,
    max_failures: u32,
    block_seconds: u64,
}

#[derive(Debug, Clone)]
struct LoginAttempt {
    failures: u32,
    blocked_until: Option<u64>,
}

impl LoginRateLimiter {
    pub fn new(max_failures: u32, block_seconds: u64) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            max_failures,
            block_seconds,
        }
    }

    pub async fn blocked_until(&self, key: &str, now: u64) -> Option<u64> {
        let mut attempts = self.inner.write().await;
        let entry = attempts.get_mut(key)?;
        match entry.blocked_until {
            Some(until) if until > now => Some(until),
            Some(_) => {
                entry.blocked_until = None;
                entry.failures = 0;
                None
            }
            None => None,
        }
    }

    pub async fn record_failure(&self, key: &str, now: u64) -> Option<u64> {
        let mut attempts = self.inner.write().await;
        let entry = attempts.entry(key.to_string()).or_insert(LoginAttempt {
            failures: 0,
            blocked_until: None,
        });

        if let Some(until) = entry.blocked_until {
            if until > now {
                return Some(until);
            }
            entry.blocked_until = None;
            entry.failures = 0;
        }

        entry.failures = entry.failures.saturating_add(1);
        if entry.failures >= self.max_failures {
            let until = now.saturating_add(self.block_seconds);
            entry.blocked_until = Some(until);
            entry.failures = 0;
            return Some(until);
        }

        None
    }

    pub async fn record_success(&self, key: &str) {
        let mut attempts = self.inner.write().await;
        attempts.remove(key);
    }
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn unix_to_rfc3339(timestamp: u64) -> String {
    let dt =
        OffsetDateTime::from_unix_timestamp(timestamp as i64).unwrap_or(OffsetDateTime::UNIX_EPOCH);
    dt.format(&Rfc3339)
        .unwrap_or_else(|_| timestamp.to_string())
}

impl From<SessionData> for SessionView {
    fn from(value: SessionData) -> Self {
        Self {
            scopes: value.scopes.into_iter().collect(),
            expires_at: unix_to_rfc3339(value.expires_at),
        }
    }
}
