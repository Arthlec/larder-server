//! Larder server domain: accounts, households and the sync rules.
//!
//! The server is deliberately ignorant of what a pantry item or a recipe is:
//! it stores opaque records per household and decides which version wins.

use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DomainError {
    #[error("username must be 3 to 32 letters, digits, '-' or '_'")]
    InvalidUsername,
    #[error("password must be at least {MIN_PASSWORD_LEN} characters")]
    WeakPassword,
    #[error("household name must be 1 to {MAX_HOUSEHOLD_NAME_LEN} characters")]
    InvalidHouseholdName,
    #[error("a sync request may carry at most {MAX_BATCH} records")]
    BatchTooLarge,
    #[error("a record payload may be at most {MAX_PAYLOAD_BYTES} bytes")]
    PayloadTooLarge,
    #[error("a record that is not a deletion needs a payload")]
    MissingPayload,
}

pub const MIN_PASSWORD_LEN: usize = 8;
pub const MAX_HOUSEHOLD_NAME_LEN: usize = 60;
pub const MAX_BATCH: usize = 1000;
pub const MAX_PAYLOAD_BYTES: usize = 256 * 1024;
/// Records returned by one pull.
pub const PULL_PAGE: usize = 500;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub id: Uuid,
    /// Stored lowercase: usernames are case-insensitive.
    pub username: String,
    pub password_hash: String,
    pub household_id: Option<Uuid>,
}

/// Normalises and checks a username.
pub fn validate_username(raw: &str) -> Result<String, DomainError> {
    let name = raw.trim().to_lowercase();
    let ok = (3..=32).contains(&name.chars().count())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if ok {
        Ok(name)
    } else {
        Err(DomainError::InvalidUsername)
    }
}

pub fn validate_password(password: &str) -> Result<(), DomainError> {
    if password.chars().count() >= MIN_PASSWORD_LEN {
        Ok(())
    } else {
        Err(DomainError::WeakPassword)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Household {
    pub id: Uuid,
    pub name: String,
    pub invite_code: String,
}

impl Household {
    /// `entropy` must be random; it becomes the id and the invite code.
    pub fn new(name: &str, id: Uuid, entropy: Uuid) -> Result<Self, DomainError> {
        let name = name.trim();
        let len = name.chars().count();
        if len == 0 || len > MAX_HOUSEHOLD_NAME_LEN {
            return Err(DomainError::InvalidHouseholdName);
        }
        Ok(Self {
            id,
            name: name.to_string(),
            invite_code: invite_code(entropy),
        })
    }
}

/// Letters and digits that are hard to confuse when read aloud or typed
/// (no 0/O, 1/I/L).
const CODE_ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
pub const INVITE_CODE_LEN: usize = 10;

/// A 10-character invite code derived from random bytes (about 49 bits).
pub fn invite_code(entropy: Uuid) -> String {
    entropy
        .as_bytes()
        .iter()
        .take(INVITE_CODE_LEN)
        .map(|b| CODE_ALPHABET[*b as usize % CODE_ALPHABET.len()] as char)
        .collect()
}

/// Makes a typed invite code comparable: case and spacing do not matter.
pub fn normalise_invite_code(raw: &str) -> String {
    raw.chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_uppercase()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordKind {
    PantryItem,
    ShoppingItem,
    Recipe,
}

impl RecordKind {
    pub const ALL: [RecordKind; 3] = [Self::PantryItem, Self::ShoppingItem, Self::Recipe];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::PantryItem => "pantry_item",
            Self::ShoppingItem => "shopping_item",
            Self::Recipe => "recipe",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }
}

/// One synced row, as sent by a device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncRecord {
    pub kind: RecordKind,
    pub id: Uuid,
    /// Milliseconds since the Unix epoch, by the clock of the device that
    /// made the change.
    pub updated_at: i64,
    pub deleted: bool,
    pub payload: String,
}

impl SyncRecord {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.payload.len() > MAX_PAYLOAD_BYTES {
            return Err(DomainError::PayloadTooLarge);
        }
        if !self.deleted && self.payload.trim().is_empty() {
            return Err(DomainError::MissingPayload);
        }
        Ok(())
    }
}

pub fn validate_batch(records: &[SyncRecord]) -> Result<(), DomainError> {
    if records.len() > MAX_BATCH {
        return Err(DomainError::BatchTooLarge);
    }
    records.iter().try_for_each(SyncRecord::validate)
}

/// Last write wins: an incoming version replaces the stored one only if it
/// is strictly newer. A tie keeps what is stored, which makes re-sending the
/// same change harmless.
pub fn incoming_wins(stored_updated_at: Option<i64>, incoming_updated_at: i64) -> bool {
    stored_updated_at.is_none_or(|stored| incoming_updated_at > stored)
}

pub mod lockout;
pub mod session;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn username_is_trimmed_and_lowercased() {
        assert_eq!(validate_username("  Ana_1 ").unwrap(), "ana_1");
    }

    #[test]
    fn bad_usernames_are_rejected() {
        for bad in ["ab", "", "has space", "é-accent", &"x".repeat(33), "a/b"] {
            assert_eq!(
                validate_username(bad),
                Err(DomainError::InvalidUsername),
                "{bad}"
            );
        }
        assert!(validate_username(&"x".repeat(32)).is_ok());
    }

    #[test]
    fn password_length_boundary() {
        assert_eq!(validate_password("1234567"), Err(DomainError::WeakPassword));
        assert!(validate_password("12345678").is_ok());
    }

    #[test]
    fn household_name_is_trimmed_and_bounded() {
        let h = Household::new(" Home ", Uuid::nil(), Uuid::nil()).unwrap();
        assert_eq!(h.name, "Home");
        assert!(Household::new("  ", Uuid::nil(), Uuid::nil()).is_err());
        assert!(Household::new(&"x".repeat(61), Uuid::nil(), Uuid::nil()).is_err());
        assert!(Household::new(&"x".repeat(60), Uuid::nil(), Uuid::nil()).is_ok());
    }

    #[test]
    fn invite_code_has_fixed_length_and_safe_alphabet() {
        for entropy in [Uuid::nil(), Uuid::max(), Uuid::new_v4()] {
            let code = invite_code(entropy);
            assert_eq!(code.len(), INVITE_CODE_LEN);
            assert!(code.bytes().all(|b| CODE_ALPHABET.contains(&b)), "{code}");
        }
    }

    #[test]
    fn different_entropy_gives_different_codes() {
        assert_ne!(invite_code(Uuid::new_v4()), invite_code(Uuid::new_v4()));
    }

    #[test]
    fn typed_invite_code_is_normalised() {
        assert_eq!(normalise_invite_code(" abcd-efgh 23 "), "ABCDEFGH23");
    }

    #[test]
    fn record_kind_text_round_trips() {
        for kind in RecordKind::ALL {
            assert_eq!(RecordKind::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(RecordKind::parse("user"), None);
    }

    fn record(deleted: bool, payload: &str) -> SyncRecord {
        SyncRecord {
            kind: RecordKind::Recipe,
            id: Uuid::nil(),
            updated_at: 1,
            deleted,
            payload: payload.into(),
        }
    }

    #[test]
    fn live_record_needs_payload_but_deletion_does_not() {
        assert_eq!(
            record(false, " ").validate(),
            Err(DomainError::MissingPayload)
        );
        assert!(record(true, "").validate().is_ok());
        assert!(record(false, "{}").validate().is_ok());
    }

    #[test]
    fn oversized_payload_is_rejected() {
        let big = "x".repeat(MAX_PAYLOAD_BYTES + 1);
        assert_eq!(
            record(false, &big).validate(),
            Err(DomainError::PayloadTooLarge)
        );
        assert!(
            record(false, &"x".repeat(MAX_PAYLOAD_BYTES))
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn batch_size_is_bounded() {
        let ok = vec![record(false, "{}"); MAX_BATCH];
        assert!(validate_batch(&ok).is_ok());
        let too_many = vec![record(false, "{}"); MAX_BATCH + 1];
        assert_eq!(validate_batch(&too_many), Err(DomainError::BatchTooLarge));
        assert!(validate_batch(&[record(false, "")]).is_err());
    }

    #[test]
    fn last_write_wins_and_ties_keep_stored() {
        assert!(incoming_wins(None, 5));
        assert!(incoming_wins(Some(4), 5));
        assert!(!incoming_wins(Some(5), 5));
        assert!(!incoming_wins(Some(6), 5));
    }
}
