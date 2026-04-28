use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::RwLock;

pub const SESSION_COOKIE_NAME: &str = "mlist_sid";

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
