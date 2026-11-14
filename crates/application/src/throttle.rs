//! In-memory record of failed attempts, per key (a username or an address).
//!
//! Kept in memory on purpose: it is cleared by a restart, which an attacker
//! cannot trigger, and it costs no database write per failed sign-in.

use std::collections::HashMap;
use std::sync::Mutex;

use larder_server_domain::lockout::{Attempts, LockoutPolicy};

/// Entries kept at most; beyond that the oldest are dropped. Bounds memory
/// when someone tries many usernames or addresses.
const MAX_ENTRIES: usize = 10_000;

pub struct Throttle {
    policy: LockoutPolicy,
    entries: Mutex<HashMap<String, Attempts>>,
}

impl Throttle {
    pub fn new(policy: LockoutPolicy) -> Self {
        Self {
            policy,
            entries: Mutex::default(),
        }
    }

    /// `Err(seconds to wait)` while `key` is locked.
    pub fn check(&self, key: &str, now: i64) -> Result<(), i64> {
        self.policy.check(self.lock().get(key), now)
    }

    pub fn failed(&self, key: &str, now: i64) {
        let mut entries = self.lock();
        if entries.len() >= MAX_ENTRIES && !entries.contains_key(key) {
            entries.retain(|_, a| !self.policy.forgotten(a, now));
            if entries.len() >= MAX_ENTRIES {
                let oldest = entries
                    .iter()
                    .min_by_key(|(_, a)| a.last_failure)
                    .map(|(k, _)| k.clone());
                if let Some(oldest) = oldest {
                    entries.remove(&oldest);
                }
            }
        }
        let previous = entries.get(key).copied();
        entries.insert(key.to_string(), self.policy.record_failure(previous, now));
    }

    pub fn succeeded(&self, key: &str) {
        self.lock().remove(key);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Attempts>> {
        // A panic while holding the lock cannot leave the map inconsistent.
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_independent_and_success_clears() {
        let t = Throttle::new(LockoutPolicy::PER_ACCOUNT);
        for _ in 0..6 {
            t.failed("ana", 0);
        }
        assert_eq!(t.check("ana", 0), Err(30));
        assert_eq!(t.check("bob", 0), Ok(()));
        t.succeeded("ana");
        assert_eq!(t.check("ana", 0), Ok(()));
    }

    #[test]
    fn memory_is_bounded() {
        let t = Throttle::new(LockoutPolicy::PER_ACCOUNT);
        for i in 0..MAX_ENTRIES + 50 {
            t.failed(&format!("user{i}"), i as i64);
        }
        assert!(t.lock().len() <= MAX_ENTRIES);
        // The newest entry is kept.
        assert!(t.lock().contains_key(&format!("user{}", MAX_ENTRIES + 49)));
    }
}
