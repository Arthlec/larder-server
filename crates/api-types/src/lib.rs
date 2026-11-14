//! The HTTP contract between the Larder app and the Larder server.
//!
//! Both sides depend on this crate, so a change to a request or response
//! shape breaks the build of whichever side was not updated, instead of
//! failing at runtime.
//!
//! | Method | Path               | Request              | Response            |
//! |--------|--------------------|----------------------|---------------------|
//! | GET    | `/health`          | -                    | `HealthResponse`    |
//! | POST   | `/auth/register`   | `Credentials`        | `TokenResponse`     |
//! | POST   | `/auth/login`      | `Credentials`        | `TokenResponse`     |
//! | POST   | `/auth/logout`     | -                    | 204, no body        |
//! | POST   | `/auth/logout-all` | -                    | 204, no body        |
//! | GET    | `/me`              | -                    | `MeResponse`        |
//! | POST   | `/households`      | `CreateHousehold`    | `HouseholdDto`      |
//! | POST   | `/households/join` | `JoinHousehold`      | `HouseholdDto`      |
//! | POST   | `/sync/push`       | `PushRequest`        | `PushResponse`      |
//! | GET    | `/sync/pull`       | `?cursor=<i64>`      | `PullResponse`      |
//!
//! The server is reached over HTTPS only. Every route except `/health`,
//! `/auth/register` and `/auth/login` needs `Authorization: Bearer <token>`.
//! A token is a session: it ends with `/auth/logout`, after 30 days unused,
//! or a year after signing in.
//!
//! Errors are an `ErrorResponse` with a 4xx/5xx status. Too many failed
//! sign-ins (or account creations) get 429 with a `Retry-After` header in
//! seconds.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenResponse {
    pub token: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeResponse {
    pub username: String,
    pub household: Option<HouseholdDto>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateHousehold {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinHousehold {
    pub invite_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HouseholdDto {
    pub name: String,
    pub invite_code: String,
}

/// Which kind of entity a sync record carries. The server stores payloads
/// opaquely; the kind only namespaces ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    PantryItem,
    ShoppingItem,
    Recipe,
}

impl EntityKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PantryItem => "pantry_item",
            Self::ShoppingItem => "shopping_item",
            Self::Recipe => "recipe",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        [Self::PantryItem, Self::ShoppingItem, Self::Recipe]
            .into_iter()
            .find(|k| k.as_str() == s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncRecordDto {
    pub kind: EntityKind,
    pub id: Uuid,
    /// Milliseconds since the Unix epoch of the last modification, as seen
    /// by the device that made it. Last write wins.
    pub updated_at: i64,
    pub deleted: bool,
    /// The entity as JSON text; empty for a deletion.
    pub payload: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushRequest {
    pub records: Vec<SyncRecordDto>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushResponse {
    /// Records that were newer than what the server had.
    pub accepted: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PullQuery {
    #[serde(default)]
    pub cursor: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PullResponse {
    /// Records changed after the requested cursor, oldest change first.
    pub records: Vec<SyncRecordDto>,
    /// Pass this as `cursor` on the next pull.
    pub cursor: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entity_kind_text_round_trips() {
        for kind in [
            EntityKind::PantryItem,
            EntityKind::ShoppingItem,
            EntityKind::Recipe,
        ] {
            assert_eq!(EntityKind::parse(kind.as_str()), Some(kind));
            // The serde name and `as_str` must agree: the server stores one
            // and the wire carries the other.
            assert_eq!(
                serde_json::to_string(&kind).unwrap(),
                format!("\"{}\"", kind.as_str())
            );
        }
        assert_eq!(EntityKind::parse("nope"), None);
    }

    #[test]
    fn sync_record_wire_format_is_stable() {
        let record = SyncRecordDto {
            kind: EntityKind::PantryItem,
            id: Uuid::nil(),
            updated_at: 42,
            deleted: false,
            payload: "{}".into(),
        };
        assert_eq!(
            serde_json::to_string(&record).unwrap(),
            r#"{"kind":"pantry_item","id":"00000000-0000-0000-0000-000000000000","updated_at":42,"deleted":false,"payload":"{}"}"#
        );
    }

    #[test]
    fn pull_query_cursor_defaults_to_zero() {
        let q: PullQuery = serde_json::from_str("{}").unwrap();
        assert_eq!(q.cursor, 0);
    }
}
