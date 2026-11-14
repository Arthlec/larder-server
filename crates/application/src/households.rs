use std::sync::Arc;

use larder_server_domain::{Household, User, normalise_invite_code};

use crate::error::{ServerError, ServerResult};
use crate::ports::{HouseholdRepository, IdGenerator, UserRepository};

#[derive(Clone)]
pub struct HouseholdService {
    households: Arc<dyn HouseholdRepository>,
    users: Arc<dyn UserRepository>,
    ids: Arc<dyn IdGenerator>,
}

impl HouseholdService {
    pub fn new(
        households: Arc<dyn HouseholdRepository>,
        users: Arc<dyn UserRepository>,
        ids: Arc<dyn IdGenerator>,
    ) -> Self {
        Self {
            households,
            users,
            ids,
        }
    }

    /// The household the user belongs to, if any.
    pub async fn of(&self, user: &User) -> ServerResult<Option<Household>> {
        match user.household_id {
            Some(id) => self.households.find_by_id(id).await,
            None => Ok(None),
        }
    }

    /// Creates a household with the user as its first member.
    pub async fn create(&self, user: &User, name: &str) -> ServerResult<Household> {
        if user.household_id.is_some() {
            return Err(ServerError::Conflict(
                "you already belong to a household".into(),
            ));
        }
        let household = Household::new(name, self.ids.random(), self.ids.random())?;
        self.households.insert(&household).await?;
        self.users.set_household(user.id, household.id).await?;
        Ok(household)
    }

    /// Joins the household that issued `invite_code`.
    pub async fn join(&self, user: &User, invite_code: &str) -> ServerResult<Household> {
        let code = normalise_invite_code(invite_code);
        let household = self
            .households
            .find_by_invite_code(&code)
            .await?
            .ok_or_else(|| ServerError::NotFound("unknown invite code".into()))?;
        match user.household_id {
            // Joining the household you are already in is a no-op.
            Some(current) if current == household.id => Ok(household),
            Some(_) => Err(ServerError::Conflict(
                "you already belong to another household".into(),
            )),
            None => {
                self.users.set_household(user.id, household.id).await?;
                Ok(household)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Fakes;
    use larder_server_domain::DomainError;

    #[tokio::test]
    async fn creator_becomes_member() {
        let fakes = Fakes::default();
        let service = fakes.households();
        let ana = fakes.user("ana").await;
        let home = service.create(&ana, " Home ").await.unwrap();
        assert_eq!(home.name, "Home");
        let ana = fakes.reload(&ana).await;
        assert_eq!(ana.household_id, Some(home.id));
        assert_eq!(service.of(&ana).await.unwrap(), Some(home));
    }

    #[tokio::test]
    async fn user_without_household_has_none() {
        let fakes = Fakes::default();
        let ana = fakes.user("ana").await;
        assert_eq!(fakes.households().of(&ana).await.unwrap(), None);
    }

    #[tokio::test]
    async fn invalid_name_is_rejected() {
        let fakes = Fakes::default();
        let ana = fakes.user("ana").await;
        assert_eq!(
            fakes.households().create(&ana, " ").await.unwrap_err(),
            ServerError::Invalid(DomainError::InvalidHouseholdName)
        );
    }

    #[tokio::test]
    async fn cannot_create_a_second_household() {
        let fakes = Fakes::default();
        let service = fakes.households();
        let ana = fakes.user("ana").await;
        service.create(&ana, "Home").await.unwrap();
        let ana = fakes.reload(&ana).await;
        assert!(matches!(
            service.create(&ana, "Other").await,
            Err(ServerError::Conflict(_))
        ));
    }

    #[tokio::test]
    async fn join_with_code_typed_loosely() {
        let fakes = Fakes::default();
        let service = fakes.households();
        let ana = fakes.user("ana").await;
        let bob = fakes.user("bob").await;
        let home = service.create(&ana, "Home").await.unwrap();
        let typed = format!(" {} ", home.invite_code.to_lowercase());
        assert_eq!(service.join(&bob, &typed).await.unwrap(), home);
        assert_eq!(fakes.reload(&bob).await.household_id, Some(home.id));
    }

    #[tokio::test]
    async fn unknown_code_is_not_found() {
        let fakes = Fakes::default();
        let bob = fakes.user("bob").await;
        assert!(matches!(
            fakes.households().join(&bob, "NOPE").await,
            Err(ServerError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn rejoining_own_household_is_a_no_op_but_switching_is_refused() {
        let fakes = Fakes::default();
        let service = fakes.households();
        let ana = fakes.user("ana").await;
        let bob = fakes.user("bob").await;
        let home = service.create(&ana, "Home").await.unwrap();
        let other = service.create(&bob, "Other").await.unwrap();
        let ana = fakes.reload(&ana).await;
        assert_eq!(service.join(&ana, &home.invite_code).await.unwrap(), home);
        assert!(matches!(
            service.join(&ana, &other.invite_code).await,
            Err(ServerError::Conflict(_))
        ));
    }
}
