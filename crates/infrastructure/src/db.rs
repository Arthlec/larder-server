use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use larder_server_application::error::{ServerError, ServerResult};
use larder_server_application::ports::{
    HouseholdRepository, RecordRepository, Sequenced, SessionRepository, UserRepository,
};
use larder_server_domain::session::Session;
use larder_server_domain::{Household, RecordKind, SyncRecord, User};
use sqlx::Row;
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions, SqliteRow,
};
use uuid::Uuid;

use crate::tls::TlsIdentity;

fn internal(e: impl std::fmt::Display) -> ServerError {
    ServerError::Internal(e.to_string())
}

/// SQLite database of the server. Implements every repository.
#[derive(Clone)]
pub struct Db {
    pool: SqlitePool,
    /// Serialises record writes so change numbers are handed out in commit
    /// order. SQLite allows one writer at a time anyway.
    write: Arc<tokio::sync::Mutex<()>>,
}

impl Db {
    /// Opens (creating if needed) the database file and applies migrations.
    pub async fn open(path: &str) -> ServerResult<Self> {
        let options = SqliteConnectOptions::from_str(&format!("sqlite://{path}"))
            .map_err(internal)?
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(options)
            .await
            .map_err(internal)?;
        Self::init(pool).await
    }

    /// A private in-memory database. For tests.
    pub async fn in_memory() -> ServerResult<Self> {
        let options = SqliteConnectOptions::from_str("sqlite::memory:")
            .map_err(internal)?
            .foreign_keys(true);
        // One connection: each in-memory connection is its own database.
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .map_err(internal)?;
        Self::init(pool).await
    }

    async fn init(pool: SqlitePool) -> ServerResult<Self> {
        sqlx::migrate!("../../migrations")
            .run(&pool)
            .await
            .map_err(internal)?;
        Ok(Self {
            pool,
            write: Arc::default(),
        })
    }

    /// The server's TLS certificate and key, created on first use and kept
    /// in the database: a backup of the file keeps the identity that phones
    /// have pinned.
    pub async fn tls_identity(&self) -> ServerResult<TlsIdentity> {
        let mut tx = self.pool.begin().await.map_err(internal)?;
        let stored: Vec<(String, String)> =
            sqlx::query_as("SELECT key, value FROM meta WHERE key IN ('tls_cert', 'tls_key')")
                .fetch_all(&mut *tx)
                .await
                .map_err(internal)?;
        let find = |name: &str| {
            stored
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
        };
        if let (Some(cert_pem), Some(key_pem)) = (find("tls_cert"), find("tls_key")) {
            return Ok(TlsIdentity { cert_pem, key_pem });
        }
        let identity = TlsIdentity::generate()?;
        for (key, value) in [
            ("tls_cert", &identity.cert_pem),
            ("tls_key", &identity.key_pem),
        ] {
            sqlx::query("INSERT OR REPLACE INTO meta(key, value) VALUES (?1, ?2)")
                .bind(key)
                .bind(value)
                .execute(&mut *tx)
                .await
                .map_err(internal)?;
        }
        tx.commit().await.map_err(internal)?;
        Ok(identity)
    }

    /// Forgets the TLS identity; a new one is made on the next start.
    pub async fn reset_tls_identity(&self) -> ServerResult<()> {
        sqlx::query("DELETE FROM meta WHERE key IN ('tls_cert', 'tls_key')")
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(internal)
    }
}

fn uuid_col(row: &SqliteRow, column: &str) -> ServerResult<Uuid> {
    let text: String = row.try_get(column).map_err(internal)?;
    text.parse().map_err(internal)
}

fn user(row: SqliteRow) -> ServerResult<User> {
    let household: Option<String> = row.try_get("household_id").map_err(internal)?;
    Ok(User {
        id: uuid_col(&row, "id")?,
        username: row.try_get("username").map_err(internal)?,
        password_hash: row.try_get("password_hash").map_err(internal)?,
        household_id: household.map(|h| h.parse().map_err(internal)).transpose()?,
    })
}

fn household(row: SqliteRow) -> ServerResult<Household> {
    Ok(Household {
        id: uuid_col(&row, "id")?,
        name: row.try_get("name").map_err(internal)?,
        invite_code: row.try_get("invite_code").map_err(internal)?,
    })
}

const USER_COLUMNS: &str = "SELECT id, username, password_hash, household_id FROM users";

#[async_trait]
impl UserRepository for Db {
    async fn find_by_username(&self, username: &str) -> ServerResult<Option<User>> {
        sqlx::query(&format!("{USER_COLUMNS} WHERE username = ?1"))
            .bind(username)
            .fetch_optional(&self.pool)
            .await
            .map_err(internal)?
            .map(user)
            .transpose()
    }

    async fn find_by_id(&self, id: Uuid) -> ServerResult<Option<User>> {
        sqlx::query(&format!("{USER_COLUMNS} WHERE id = ?1"))
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(internal)?
            .map(user)
            .transpose()
    }

    async fn insert(&self, user: &User) -> ServerResult<bool> {
        // ON CONFLICT DO NOTHING makes "is the name free?" and the insert
        // one atomic step.
        let result = sqlx::query(
            "INSERT INTO users(id, username, password_hash, household_id)
             VALUES (?1, ?2, ?3, ?4) ON CONFLICT(username) DO NOTHING",
        )
        .bind(user.id.to_string())
        .bind(&user.username)
        .bind(&user.password_hash)
        .bind(user.household_id.map(|h| h.to_string()))
        .execute(&self.pool)
        .await
        .map_err(internal)?;
        Ok(result.rows_affected() == 1)
    }

    async fn set_household(&self, user_id: Uuid, household_id: Uuid) -> ServerResult<()> {
        sqlx::query("UPDATE users SET household_id = ?2 WHERE id = ?1")
            .bind(user_id.to_string())
            .bind(household_id.to_string())
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(internal)
    }
}

#[async_trait]
impl HouseholdRepository for Db {
    async fn insert(&self, household: &Household) -> ServerResult<()> {
        sqlx::query("INSERT INTO households(id, name, invite_code) VALUES (?1, ?2, ?3)")
            .bind(household.id.to_string())
            .bind(&household.name)
            .bind(&household.invite_code)
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(internal)
    }

    async fn find_by_id(&self, id: Uuid) -> ServerResult<Option<Household>> {
        sqlx::query("SELECT id, name, invite_code FROM households WHERE id = ?1")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(internal)?
            .map(household)
            .transpose()
    }

    async fn find_by_invite_code(&self, code: &str) -> ServerResult<Option<Household>> {
        sqlx::query("SELECT id, name, invite_code FROM households WHERE invite_code = ?1")
            .bind(code)
            .fetch_optional(&self.pool)
            .await
            .map_err(internal)?
            .map(household)
            .transpose()
    }
}

#[async_trait]
impl RecordRepository for Db {
    async fn store_newer(&self, household_id: Uuid, records: &[SyncRecord]) -> ServerResult<usize> {
        let _writing = self.write.lock().await;
        let mut tx = self.pool.begin().await.map_err(internal)?;
        let mut seq: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) FROM records")
            .fetch_one(&mut *tx)
            .await
            .map_err(internal)?;
        let household = household_id.to_string();
        let mut accepted = 0;
        for record in records {
            // The WHERE clause is `larder_server_domain::incoming_wins`
            // expressed in SQL, so the check and the write are one statement.
            // A test below keeps the two in agreement.
            let result = sqlx::query(
                "INSERT INTO records(household_id, kind, id, updated_at, deleted, payload, seq)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(household_id, kind, id) DO UPDATE SET
                    updated_at = excluded.updated_at, deleted = excluded.deleted,
                    payload = excluded.payload, seq = excluded.seq
                 WHERE excluded.updated_at > records.updated_at",
            )
            .bind(&household)
            .bind(record.kind.as_str())
            .bind(record.id.to_string())
            .bind(record.updated_at)
            .bind(record.deleted)
            .bind(&record.payload)
            .bind(seq + 1)
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
            if result.rows_affected() == 1 {
                seq += 1;
                accepted += 1;
            }
        }
        tx.commit().await.map_err(internal)?;
        Ok(accepted)
    }

    async fn changed_since(
        &self,
        household_id: Uuid,
        cursor: i64,
        limit: usize,
    ) -> ServerResult<Vec<Sequenced>> {
        let rows = sqlx::query(
            "SELECT kind, id, updated_at, deleted, payload, seq FROM records
             WHERE household_id = ?1 AND seq > ?2 ORDER BY seq LIMIT ?3",
        )
        .bind(household_id.to_string())
        .bind(cursor)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(internal)?;
        rows.into_iter()
            .map(|row| {
                let kind: String = row.try_get("kind").map_err(internal)?;
                Ok(Sequenced {
                    seq: row.try_get("seq").map_err(internal)?,
                    record: SyncRecord {
                        kind: RecordKind::parse(&kind)
                            .ok_or_else(|| internal(format!("unknown record kind {kind}")))?,
                        id: uuid_col(&row, "id")?,
                        updated_at: row.try_get("updated_at").map_err(internal)?,
                        deleted: row.try_get("deleted").map_err(internal)?,
                        payload: row.try_get("payload").map_err(internal)?,
                    },
                })
            })
            .collect()
    }
}

#[async_trait]
impl SessionRepository for Db {
    async fn create(&self, token_hash: &str, session: &Session) -> ServerResult<()> {
        sqlx::query(
            "INSERT INTO sessions(token_hash, user_id, created_at, last_used_at)
             VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(token_hash)
        .bind(session.user_id.to_string())
        .bind(session.created_at)
        .bind(session.last_used_at)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(internal)
    }

    async fn find(&self, token_hash: &str) -> ServerResult<Option<Session>> {
        sqlx::query("SELECT user_id, created_at, last_used_at FROM sessions WHERE token_hash = ?1")
            .bind(token_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(internal)?
            .map(|row| {
                Ok(Session {
                    user_id: uuid_col(&row, "user_id")?,
                    created_at: row.try_get("created_at").map_err(internal)?,
                    last_used_at: row.try_get("last_used_at").map_err(internal)?,
                })
            })
            .transpose()
    }

    async fn touch(&self, token_hash: &str, now: i64) -> ServerResult<()> {
        sqlx::query("UPDATE sessions SET last_used_at = ?2 WHERE token_hash = ?1")
            .bind(token_hash)
            .bind(now)
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(internal)
    }

    async fn delete(&self, token_hash: &str) -> ServerResult<()> {
        sqlx::query("DELETE FROM sessions WHERE token_hash = ?1")
            .bind(token_hash)
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(internal)
    }

    async fn delete_for_user(&self, user_id: Uuid) -> ServerResult<u64> {
        sqlx::query("DELETE FROM sessions WHERE user_id = ?1")
            .bind(user_id.to_string())
            .execute(&self.pool)
            .await
            .map(|r| r.rows_affected())
            .map_err(internal)
    }

    async fn purge(&self, idle_cutoff: i64, created_cutoff: i64) -> ServerResult<u64> {
        sqlx::query("DELETE FROM sessions WHERE last_used_at <= ?1 OR created_at <= ?2")
            .bind(idle_cutoff)
            .bind(created_cutoff)
            .execute(&self.pool)
            .await
            .map(|r| r.rows_affected())
            .map_err(internal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use larder_server_domain::incoming_wins;

    async fn db() -> Db {
        Db::in_memory().await.unwrap()
    }

    fn a_user(name: &str) -> User {
        User {
            id: Uuid::new_v4(),
            username: name.into(),
            password_hash: "hash".into(),
            household_id: None,
        }
    }

    async fn a_household(db: &Db, code: &str) -> Household {
        let h = Household {
            id: Uuid::new_v4(),
            name: "Home".into(),
            invite_code: code.into(),
        };
        HouseholdRepository::insert(db, &h).await.unwrap();
        h
    }

    fn record(id: u128, updated_at: i64) -> SyncRecord {
        SyncRecord {
            kind: RecordKind::ShoppingItem,
            id: Uuid::from_u128(id),
            updated_at,
            deleted: false,
            payload: format!("v{updated_at}"),
        }
    }

    #[tokio::test]
    async fn user_round_trips_by_name_and_id() {
        let db = db().await;
        let ana = a_user("ana");
        assert!(UserRepository::insert(&db, &ana).await.unwrap());
        assert_eq!(db.find_by_username("ana").await.unwrap(), Some(ana.clone()));
        assert_eq!(
            UserRepository::find_by_id(&db, ana.id).await.unwrap(),
            Some(ana)
        );
        assert_eq!(db.find_by_username("bob").await.unwrap(), None);
    }

    #[tokio::test]
    async fn duplicate_username_is_refused_without_error() {
        let db = db().await;
        assert!(UserRepository::insert(&db, &a_user("ana")).await.unwrap());
        assert!(!UserRepository::insert(&db, &a_user("ana")).await.unwrap());
    }

    #[tokio::test]
    async fn household_round_trips_and_membership_is_stored() {
        let db = db().await;
        let home = a_household(&db, "CODE").await;
        assert_eq!(
            HouseholdRepository::find_by_id(&db, home.id).await.unwrap(),
            Some(home.clone())
        );
        assert_eq!(
            db.find_by_invite_code("CODE").await.unwrap(),
            Some(home.clone())
        );
        assert_eq!(db.find_by_invite_code("NOPE").await.unwrap(), None);
        let ana = a_user("ana");
        UserRepository::insert(&db, &ana).await.unwrap();
        db.set_household(ana.id, home.id).await.unwrap();
        let reloaded = UserRepository::find_by_id(&db, ana.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reloaded.household_id, Some(home.id));
    }

    #[tokio::test]
    async fn records_are_stored_and_returned_in_change_order() {
        let db = db().await;
        let home = a_household(&db, "A").await;
        assert_eq!(
            db.store_newer(home.id, &[record(1, 10), record(2, 5)])
                .await
                .unwrap(),
            2
        );
        let changes = db.changed_since(home.id, 0, 100).await.unwrap();
        assert_eq!(
            changes,
            [
                Sequenced {
                    seq: 1,
                    record: record(1, 10)
                },
                Sequenced {
                    seq: 2,
                    record: record(2, 5)
                },
            ]
        );
        assert_eq!(db.changed_since(home.id, 1, 100).await.unwrap().len(), 1);
        assert_eq!(db.changed_since(home.id, 0, 1).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn sql_conflict_rule_agrees_with_the_domain_rule() {
        for (stored, incoming) in [(10, 9), (10, 10), (10, 11)] {
            let db = db().await;
            let home = a_household(&db, "A").await;
            db.store_newer(home.id, &[record(1, stored)]).await.unwrap();
            let accepted = db
                .store_newer(home.id, &[record(1, incoming)])
                .await
                .unwrap();
            assert_eq!(
                accepted == 1,
                incoming_wins(Some(stored), incoming),
                "stored {stored}, incoming {incoming}"
            );
            let kept = db.changed_since(home.id, 0, 10).await.unwrap();
            assert_eq!(kept.len(), 1);
            assert_eq!(kept[0].record.updated_at, stored.max(incoming));
        }
    }

    #[tokio::test]
    async fn replaced_record_gets_a_higher_change_number() {
        let db = db().await;
        let home = a_household(&db, "A").await;
        db.store_newer(home.id, &[record(1, 10), record(2, 10)])
            .await
            .unwrap();
        db.store_newer(home.id, &[record(1, 20)]).await.unwrap();
        let changes = db.changed_since(home.id, 2, 10).await.unwrap();
        assert_eq!(
            changes,
            [Sequenced {
                seq: 3,
                record: record(1, 20)
            }]
        );
    }

    #[tokio::test]
    async fn households_do_not_see_each_other() {
        let db = db().await;
        let a = a_household(&db, "A").await;
        let b = a_household(&db, "B").await;
        db.store_newer(a.id, &[record(1, 10)]).await.unwrap();
        db.store_newer(b.id, &[record(1, 3)]).await.unwrap();
        assert_eq!(
            db.changed_since(a.id, 0, 10).await.unwrap()[0].record,
            record(1, 10)
        );
        assert_eq!(
            db.changed_since(b.id, 0, 10).await.unwrap()[0].record,
            record(1, 3)
        );
    }

    #[tokio::test]
    async fn same_id_of_different_kinds_are_different_records() {
        let db = db().await;
        let home = a_household(&db, "A").await;
        let mut recipe = record(1, 10);
        recipe.kind = RecordKind::Recipe;
        assert_eq!(
            db.store_newer(home.id, &[record(1, 10), recipe])
                .await
                .unwrap(),
            2
        );
    }

    #[tokio::test]
    async fn tls_identity_is_created_once_and_can_be_reset() {
        let db = db().await;
        let first = db.tls_identity().await.unwrap();
        assert_eq!(db.tls_identity().await.unwrap(), first);
        db.reset_tls_identity().await.unwrap();
        assert_ne!(db.tls_identity().await.unwrap(), first);
    }

    fn session(user: &User, created_at: i64, last_used_at: i64) -> Session {
        Session {
            user_id: user.id,
            created_at,
            last_used_at,
        }
    }

    #[tokio::test]
    async fn sessions_are_stored_touched_and_deleted() {
        let db = db().await;
        let ana = a_user("ana");
        let bob = a_user("bob");
        UserRepository::insert(&db, &ana).await.unwrap();
        UserRepository::insert(&db, &bob).await.unwrap();
        db.create("h1", &session(&ana, 10, 10)).await.unwrap();
        db.create("h2", &session(&ana, 20, 20)).await.unwrap();
        db.create("h3", &session(&bob, 30, 30)).await.unwrap();

        assert_eq!(db.find("h1").await.unwrap(), Some(session(&ana, 10, 10)));
        assert_eq!(db.find("nope").await.unwrap(), None);
        db.touch("h1", 99).await.unwrap();
        assert_eq!(db.find("h1").await.unwrap(), Some(session(&ana, 10, 99)));

        db.delete("h1").await.unwrap();
        assert_eq!(db.find("h1").await.unwrap(), None);
        assert_eq!(db.delete_for_user(ana.id).await.unwrap(), 1);
        assert!(db.find("h3").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn purge_uses_both_cutoffs() {
        let db = db().await;
        let ana = a_user("ana");
        UserRepository::insert(&db, &ana).await.unwrap();
        db.create("idle", &session(&ana, 50, 5)).await.unwrap();
        db.create("old", &session(&ana, 1, 60)).await.unwrap();
        db.create("fine", &session(&ana, 50, 60)).await.unwrap();
        assert_eq!(db.purge(5, 1).await.unwrap(), 2);
        assert!(db.find("fine").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn data_survives_reopening_the_file() {
        let dir = std::env::temp_dir().join(format!("larder-server-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("server.db");
        let path = path.to_str().unwrap();
        let ana = a_user("ana");
        let identity = {
            let db = Db::open(path).await.unwrap();
            UserRepository::insert(&db, &ana).await.unwrap();
            db.tls_identity().await.unwrap()
        };
        let db = Db::open(path).await.unwrap();
        assert_eq!(db.find_by_username("ana").await.unwrap(), Some(ana));
        assert_eq!(db.tls_identity().await.unwrap(), identity);
        drop(db);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
