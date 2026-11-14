use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use larder_server_application::error::{ServerError, ServerResult};
use larder_server_application::ports::{
    HouseholdRepository, RecordRepository, Sequenced, UserRepository,
};
use larder_server_domain::{Household, RecordKind, SyncRecord, User};
use sqlx::Row;
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions, SqliteRow,
};
use uuid::Uuid;

fn internal(e: impl std::fmt::Display) -> ServerError {
    ServerError::Internal(e.to_string())
}

/// SQLite database of the server. Implements all three repositories.
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

    /// The token signing secret, created on first use and kept in the
    /// database so tokens survive a restart without any configuration.
    pub async fn signing_secret(&self) -> ServerResult<String> {
        let fresh = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        sqlx::query("INSERT OR IGNORE INTO meta(key, value) VALUES ('jwt_secret', ?1)")
            .bind(&fresh)
            .execute(&self.pool)
            .await
            .map_err(internal)?;
        sqlx::query_scalar("SELECT value FROM meta WHERE key = 'jwt_secret'")
            .fetch_one(&self.pool)
            .await
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
    async fn signing_secret_is_created_once() {
        let db = db().await;
        let first = db.signing_secret().await.unwrap();
        assert_eq!(first.len(), 64);
        assert_eq!(db.signing_secret().await.unwrap(), first);
    }

    #[tokio::test]
    async fn data_survives_reopening_the_file() {
        let dir = std::env::temp_dir().join(format!("larder-server-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("server.db");
        let path = path.to_str().unwrap();
        let ana = a_user("ana");
        let secret = {
            let db = Db::open(path).await.unwrap();
            UserRepository::insert(&db, &ana).await.unwrap();
            db.signing_secret().await.unwrap()
        };
        let db = Db::open(path).await.unwrap();
        assert_eq!(db.find_by_username("ana").await.unwrap(), Some(ana));
        assert_eq!(db.signing_secret().await.unwrap(), secret);
        drop(db);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
