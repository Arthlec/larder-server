//! Lockout after repeated failures, to slow down password guessing.
//!
//! Times are seconds since the Unix epoch, passed in, so the rules are
//! testable without a clock.

/// How many failures are tolerated and how long the lockout lasts after.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockoutPolicy {
    /// Failures without any penalty.
    pub free_failures: u32,
    /// Lockout after the first failure beyond the free ones, in seconds.
    /// Each further failure doubles it.
    pub base_lock_secs: i64,
    pub max_lock_secs: i64,
    /// Failures are forgotten after this long without a new one.
    pub forget_after_secs: i64,
}

impl LockoutPolicy {
    /// Sign-ins for one username: 5 tries, then 30 s doubling up to 15 min.
    pub const PER_ACCOUNT: Self = Self {
        free_failures: 5,
        base_lock_secs: 30,
        max_lock_secs: 15 * 60,
        forget_after_secs: 15 * 60,
    };

    /// Sign-ins from one address, whatever the username. Looser, so a
    /// household behind one address is not locked out by one person, but it
    /// stops one address from trying a password against many usernames.
    pub const PER_ADDRESS: Self = Self {
        free_failures: 20,
        ..Self::PER_ACCOUNT
    };

    /// Account creation from one address: each one costs a password hash.
    /// Every attempt counts; after 10, wait an hour.
    pub const REGISTRATIONS: Self = Self {
        free_failures: 10,
        base_lock_secs: 60 * 60,
        max_lock_secs: 60 * 60,
        forget_after_secs: 60 * 60,
    };

    /// The state after one more failure at `now`.
    pub fn record_failure(&self, previous: Option<Attempts>, now: i64) -> Attempts {
        let failures = match previous {
            Some(p) if !self.forgotten(&p, now) => p.failures + 1,
            _ => 1,
        };
        let locked_until = match failures.checked_sub(self.free_failures + 1) {
            None => now,
            Some(extra) => {
                let lock = self
                    .base_lock_secs
                    .saturating_mul(1i64 << extra.min(30))
                    .min(self.max_lock_secs);
                now + lock
            }
        };
        Attempts {
            failures,
            last_failure: now,
            locked_until,
        }
    }

    /// `Err(seconds to wait)` while locked.
    pub fn check(&self, state: Option<&Attempts>, now: i64) -> Result<(), i64> {
        match state {
            Some(s) if s.locked_until > now => Err(s.locked_until - now),
            _ => Ok(()),
        }
    }

    /// Whether the state can be dropped: no lock and nothing left to count.
    pub fn forgotten(&self, state: &Attempts, now: i64) -> bool {
        state.locked_until <= now && now - state.last_failure >= self.forget_after_secs
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attempts {
    pub failures: u32,
    pub last_failure: i64,
    pub locked_until: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: LockoutPolicy = LockoutPolicy::PER_ACCOUNT;

    fn fail_times(n: u32, now: i64) -> Option<Attempts> {
        (0..n).fold(None, |state, _| Some(P.record_failure(state, now)))
    }

    #[test]
    fn free_failures_do_not_lock() {
        let state = fail_times(5, 100);
        assert_eq!(P.check(state.as_ref(), 100), Ok(()));
    }

    #[test]
    fn the_next_failure_locks_for_the_base_time() {
        let state = fail_times(6, 100);
        assert_eq!(P.check(state.as_ref(), 100), Err(30));
        assert_eq!(P.check(state.as_ref(), 129), Err(1));
        assert_eq!(P.check(state.as_ref(), 130), Ok(()));
    }

    #[test]
    fn lock_doubles_and_is_capped() {
        assert_eq!(P.check(fail_times(7, 0).as_ref(), 0), Err(60));
        assert_eq!(P.check(fail_times(8, 0).as_ref(), 0), Err(120));
        assert_eq!(P.check(fail_times(11, 0).as_ref(), 0), Err(900));
        assert_eq!(P.check(fail_times(200, 0).as_ref(), 0), Err(900));
    }

    #[test]
    fn failures_are_forgotten_after_a_quiet_period() {
        let state = fail_times(5, 0);
        let later = P.record_failure(state, 15 * 60);
        assert_eq!(later.failures, 1);
        let soon = P.record_failure(state, 15 * 60 - 1);
        assert_eq!(soon.failures, 6);
    }

    #[test]
    fn a_locked_state_is_never_forgotten_early() {
        let state = fail_times(11, 0).unwrap();
        assert!(!P.forgotten(&state, 899));
        assert!(P.forgotten(&state, 900));
    }

    #[test]
    fn registrations_allow_ten_per_hour() {
        let r = LockoutPolicy::REGISTRATIONS;
        let ten = (0..10).fold(None, |s, _| Some(r.record_failure(s, 0)));
        assert_eq!(r.check(ten.as_ref(), 0), Ok(()));
        let eleven = Some(r.record_failure(ten, 0));
        assert_eq!(r.check(eleven.as_ref(), 0), Err(3600));
    }
}
