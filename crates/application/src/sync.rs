use std::sync::Arc;

use larder_server_domain::{PULL_PAGE, SyncRecord, User, validate_batch};

use crate::error::{ServerError, ServerResult};
use crate::ports::RecordRepository;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullPage {
    pub records: Vec<SyncRecord>,
    /// Cursor to send with the next pull.
    pub cursor: i64,
}

#[derive(Clone)]
pub struct SyncService {
    records: Arc<dyn RecordRepository>,
}

impl SyncService {
    pub fn new(records: Arc<dyn RecordRepository>) -> Self {
        Self { records }
    }

    /// Stores the records that are newer than what the household has.
    /// Returns how many were accepted.
    pub async fn push(&self, user: &User, records: &[SyncRecord]) -> ServerResult<usize> {
        let household = user.household_id.ok_or(ServerError::NoHousehold)?;
        validate_batch(records)?;
        if records.is_empty() {
            return Ok(0);
        }
        self.records.store_newer(household, records).await
    }

    /// The household's changes after `cursor`, one page at a time.
    pub async fn pull(&self, user: &User, cursor: i64) -> ServerResult<PullPage> {
        let household = user.household_id.ok_or(ServerError::NoHousehold)?;
        let cursor = cursor.max(0);
        let changes = self
            .records
            .changed_since(household, cursor, PULL_PAGE)
            .await?;
        Ok(PullPage {
            cursor: changes.last().map_or(cursor, |c| c.seq),
            records: changes.into_iter().map(|c| c.record).collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Fakes;
    use larder_server_domain::{DomainError, MAX_BATCH, RecordKind};
    use uuid::Uuid;

    fn record(id: u128, updated_at: i64) -> SyncRecord {
        SyncRecord {
            kind: RecordKind::PantryItem,
            id: Uuid::from_u128(id),
            updated_at,
            deleted: false,
            payload: format!("{{\"v\":{updated_at}}}"),
        }
    }

    async fn member(fakes: &Fakes, name: &str, household: Option<&User>) -> User {
        let user = fakes.user(name).await;
        let service = fakes.households();
        match household {
            None => {
                service.create(&user, name).await.unwrap();
            }
            Some(owner) => {
                let code = service.of(owner).await.unwrap().unwrap().invite_code;
                service.join(&user, &code).await.unwrap();
            }
        }
        fakes.reload(&user).await
    }

    #[tokio::test]
    async fn user_without_household_cannot_sync() {
        let fakes = Fakes::default();
        let sync = fakes.sync();
        let loner = fakes.user("loner").await;
        assert_eq!(
            sync.push(&loner, &[record(1, 1)]).await.unwrap_err(),
            ServerError::NoHousehold
        );
        assert_eq!(
            sync.pull(&loner, 0).await.unwrap_err(),
            ServerError::NoHousehold
        );
    }

    #[tokio::test]
    async fn pushed_records_reach_other_members() {
        let fakes = Fakes::default();
        let sync = fakes.sync();
        let ana = member(&fakes, "ana", None).await;
        let bob = member(&fakes, "bob", Some(&ana)).await;
        assert_eq!(
            sync.push(&ana, &[record(1, 10), record(2, 11)])
                .await
                .unwrap(),
            2
        );
        let page = sync.pull(&bob, 0).await.unwrap();
        assert_eq!(page.records, [record(1, 10), record(2, 11)]);
        assert_eq!(page.cursor, 2);
    }

    #[tokio::test]
    async fn households_are_isolated() {
        let fakes = Fakes::default();
        let sync = fakes.sync();
        let ana = member(&fakes, "ana", None).await;
        let eve = member(&fakes, "eve", None).await;
        sync.push(&ana, &[record(1, 10)]).await.unwrap();
        assert!(sync.pull(&eve, 0).await.unwrap().records.is_empty());
        // Same record id in another household is a different record.
        assert_eq!(sync.push(&eve, &[record(1, 5)]).await.unwrap(), 1);
        assert_eq!(sync.pull(&ana, 0).await.unwrap().records, [record(1, 10)]);
    }

    #[tokio::test]
    async fn older_or_equal_version_is_not_accepted() {
        let fakes = Fakes::default();
        let sync = fakes.sync();
        let ana = member(&fakes, "ana", None).await;
        sync.push(&ana, &[record(1, 10)]).await.unwrap();
        assert_eq!(sync.push(&ana, &[record(1, 9)]).await.unwrap(), 0);
        assert_eq!(sync.push(&ana, &[record(1, 10)]).await.unwrap(), 0);
        assert_eq!(sync.pull(&ana, 0).await.unwrap().records, [record(1, 10)]);
    }

    #[tokio::test]
    async fn newer_version_replaces_and_is_seen_after_the_old_cursor() {
        let fakes = Fakes::default();
        let sync = fakes.sync();
        let ana = member(&fakes, "ana", None).await;
        sync.push(&ana, &[record(1, 10)]).await.unwrap();
        let cursor = sync.pull(&ana, 0).await.unwrap().cursor;
        assert_eq!(sync.push(&ana, &[record(1, 20)]).await.unwrap(), 1);
        let page = sync.pull(&ana, cursor).await.unwrap();
        assert_eq!(page.records, [record(1, 20)]);
        assert!(page.cursor > cursor);
    }

    #[tokio::test]
    async fn pull_with_nothing_new_keeps_the_cursor() {
        let fakes = Fakes::default();
        let sync = fakes.sync();
        let ana = member(&fakes, "ana", None).await;
        sync.push(&ana, &[record(1, 10)]).await.unwrap();
        let page = sync.pull(&ana, 1).await.unwrap();
        assert!(page.records.is_empty());
        assert_eq!(page.cursor, 1);
        assert_eq!(sync.pull(&ana, -5).await.unwrap().cursor, 1);
    }

    #[tokio::test]
    async fn pull_is_paged() {
        let fakes = Fakes::default();
        let sync = fakes.sync();
        let ana = member(&fakes, "ana", None).await;
        let many: Vec<_> = (0..PULL_PAGE as u128 + 3).map(|i| record(i, 1)).collect();
        sync.push(&ana, &many).await.unwrap();
        let first = sync.pull(&ana, 0).await.unwrap();
        assert_eq!(first.records.len(), PULL_PAGE);
        let second = sync.pull(&ana, first.cursor).await.unwrap();
        assert_eq!(second.records.len(), 3);
    }

    #[tokio::test]
    async fn invalid_batch_is_rejected_whole() {
        let fakes = Fakes::default();
        let sync = fakes.sync();
        let ana = member(&fakes, "ana", None).await;
        let mut bad = record(2, 1);
        bad.payload.clear();
        assert_eq!(
            sync.push(&ana, &[record(1, 1), bad]).await.unwrap_err(),
            ServerError::Invalid(DomainError::MissingPayload)
        );
        let too_many: Vec<_> = (0..MAX_BATCH as u128 + 1).map(|i| record(i, 1)).collect();
        assert_eq!(
            sync.push(&ana, &too_many).await.unwrap_err(),
            ServerError::Invalid(DomainError::BatchTooLarge)
        );
        assert!(sync.pull(&ana, 0).await.unwrap().records.is_empty());
    }

    #[tokio::test]
    async fn deletion_is_stored_and_delivered() {
        let fakes = Fakes::default();
        let sync = fakes.sync();
        let ana = member(&fakes, "ana", None).await;
        sync.push(&ana, &[record(1, 10)]).await.unwrap();
        let mut tombstone = record(1, 20);
        tombstone.deleted = true;
        tombstone.payload.clear();
        sync.push(&ana, &[tombstone.clone()]).await.unwrap();
        assert_eq!(sync.pull(&ana, 0).await.unwrap().records, [tombstone]);
    }
}
