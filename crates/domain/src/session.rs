//! How long a sign-in lasts. Times are seconds since the Unix epoch.

use uuid::Uuid;

/// A session ends after this long without being used...
pub const IDLE_LIMIT_SECS: i64 = 30 * 24 * 60 * 60;
/// ...and in any case this long after signing in.
pub const ABSOLUTE_LIMIT_SECS: i64 = 365 * 24 * 60 * 60;
/// "Last used" is recorded at most this often, to avoid a write per request.
pub const TOUCH_INTERVAL_SECS: i64 = 60 * 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub user_id: Uuid,
    pub created_at: i64,
    pub last_used_at: i64,
}

impl Session {
    pub fn is_valid(&self, now: i64) -> bool {
        now - self.last_used_at < IDLE_LIMIT_SECS && now - self.created_at < ABSOLUTE_LIMIT_SECS
    }

    pub fn needs_touch(&self, now: i64) -> bool {
        now - self.last_used_at >= TOUCH_INTERVAL_SECS
    }
}

/// Sessions last used before the first cutoff or created before the second
/// have expired.
pub fn expiry_cutoffs(now: i64) -> (i64, i64) {
    (now - IDLE_LIMIT_SECS, now - ABSOLUTE_LIMIT_SECS)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 24 * 60 * 60;

    fn session(created_at: i64, last_used_at: i64) -> Session {
        Session {
            user_id: Uuid::nil(),
            created_at,
            last_used_at,
        }
    }

    #[test]
    fn expires_after_thirty_idle_days() {
        let s = session(0, 0);
        assert!(s.is_valid(30 * DAY - 1));
        assert!(!s.is_valid(30 * DAY));
    }

    #[test]
    fn use_extends_it_but_not_beyond_a_year() {
        let s = session(0, 364 * DAY);
        assert!(s.is_valid(365 * DAY - 1));
        assert!(!s.is_valid(365 * DAY));
    }

    #[test]
    fn touched_at_most_hourly() {
        let s = session(0, 100);
        assert!(!s.needs_touch(100 + 3599));
        assert!(s.needs_touch(100 + 3600));
    }

    #[test]
    fn cutoffs_agree_with_is_valid() {
        let now = 400 * DAY;
        let (idle, created) = expiry_cutoffs(now);
        assert!(!session(created, now).is_valid(now));
        assert!(session(created + 1, now).is_valid(now));
        assert!(!session(now - DAY, idle).is_valid(now));
        assert!(session(now - DAY, idle + 1).is_valid(now));
    }
}
