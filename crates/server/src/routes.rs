use std::net::{IpAddr, SocketAddr};

use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{ConnectInfo, DefaultBodyLimit, FromRequestParts, Query, State};
use axum::http::header::{AUTHORIZATION, RETRY_AFTER};
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use larder_api_types as api;
use larder_server_application::ServerError;
use larder_server_domain::{Household, RecordKind, SyncRecord, User};

use crate::AppState;

/// Enough for a full batch of ordinary records; see MAX_BATCH in the domain.
const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/auth/register", post(register))
        .route("/auth/login", post(login))
        .route("/auth/logout", post(logout))
        .route("/auth/logout-all", post(logout_all))
        .route("/me", get(me))
        .route("/households", post(create_household))
        .route("/households/join", post(join_household))
        .route("/sync/push", post(push))
        .route("/sync/pull", get(pull))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

/// Any failure, rendered as an `ErrorResponse` with a fitting status.
struct ApiError(StatusCode, String, Option<i64>);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut response = (self.0, Json(api::ErrorResponse { error: self.1 })).into_response();
        if let Some(secs) = self.2 {
            response
                .headers_mut()
                .insert(RETRY_AFTER, HeaderValue::from(secs.max(1)));
        }
        response
    }
}

impl From<ServerError> for ApiError {
    fn from(error: ServerError) -> Self {
        let status = match &error {
            ServerError::Invalid(_) => StatusCode::BAD_REQUEST,
            ServerError::BadCredentials | ServerError::BadToken => StatusCode::UNAUTHORIZED,
            ServerError::TooManyAttempts { .. } => StatusCode::TOO_MANY_REQUESTS,
            ServerError::RegistrationClosed => StatusCode::FORBIDDEN,
            ServerError::Conflict(_) | ServerError::NoHousehold => StatusCode::CONFLICT,
            ServerError::NotFound(_) => StatusCode::NOT_FOUND,
            ServerError::Internal(detail) => {
                // The detail goes to the server log, never to the client.
                eprintln!("internal error: {detail}");
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        let retry_after = match &error {
            ServerError::TooManyAttempts { retry_after_secs } => Some(*retry_after_secs),
            _ => None,
        };
        ApiError(status, error.to_string(), retry_after)
    }
}

impl From<JsonRejection> for ApiError {
    fn from(rejection: JsonRejection) -> Self {
        ApiError(rejection.status(), rejection.body_text(), None)
    }
}

impl From<QueryRejection> for ApiError {
    fn from(rejection: QueryRejection) -> Self {
        ApiError(rejection.status(), rejection.body_text(), None)
    }
}

type ApiResult<T> = Result<Json<T>, ApiError>;

/// The signed-in user, from the `Authorization: Bearer` header.
struct Auth(User);

/// The bearer token itself, for ending its session.
struct Token(String);

impl FromRequestParts<AppState> for Token {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _: &AppState) -> Result<Self, ApiError> {
        let token = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or(ServerError::BadToken)?;
        Ok(Token(token.trim().to_string()))
    }
}

impl FromRequestParts<AppState> for Auth {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let Token(token) = Token::from_request_parts(parts, state).await?;
        Ok(Auth(state.auth.authenticate(&token).await?))
    }
}

/// The address the request came from. Unknown only when the router is
/// called without a network listener, as in tests.
struct ClientIp(Option<IpAddr>);

impl<S: Send + Sync> FromRequestParts<S> for ClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        Ok(ClientIp(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|info| info.0.ip()),
        ))
    }
}

fn household_dto(household: Household) -> api::HouseholdDto {
    api::HouseholdDto {
        name: household.name,
        invite_code: household.invite_code,
    }
}

fn kind_from_dto(kind: api::EntityKind) -> RecordKind {
    match kind {
        api::EntityKind::PantryItem => RecordKind::PantryItem,
        api::EntityKind::ShoppingItem => RecordKind::ShoppingItem,
        api::EntityKind::Recipe => RecordKind::Recipe,
    }
}

fn kind_to_dto(kind: RecordKind) -> api::EntityKind {
    match kind {
        RecordKind::PantryItem => api::EntityKind::PantryItem,
        RecordKind::ShoppingItem => api::EntityKind::ShoppingItem,
        RecordKind::Recipe => api::EntityKind::Recipe,
    }
}

async fn health() -> Json<api::HealthResponse> {
    Json(api::HealthResponse {
        status: "ok".into(),
        version: env!("CARGO_PKG_VERSION").into(),
    })
}

async fn register(
    State(state): State<AppState>,
    ClientIp(client): ClientIp,
    body: Result<Json<api::Credentials>, JsonRejection>,
) -> ApiResult<api::TokenResponse> {
    let Json(credentials) = body?;
    let token = state
        .auth
        .register(&credentials.username, &credentials.password, client)
        .await?;
    Ok(Json(api::TokenResponse { token }))
}

async fn login(
    State(state): State<AppState>,
    ClientIp(client): ClientIp,
    body: Result<Json<api::Credentials>, JsonRejection>,
) -> ApiResult<api::TokenResponse> {
    let Json(credentials) = body?;
    let token = state
        .auth
        .login(&credentials.username, &credentials.password, client)
        .await?;
    Ok(Json(api::TokenResponse { token }))
}

/// Ends this device's session. Succeeds even if it had already ended.
async fn logout(
    State(state): State<AppState>,
    Token(token): Token,
) -> Result<StatusCode, ApiError> {
    state.auth.logout(&token).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Ends every session of the account, on every device.
async fn logout_all(
    State(state): State<AppState>,
    Auth(user): Auth,
) -> Result<StatusCode, ApiError> {
    state.auth.logout_everywhere(&user).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn me(State(state): State<AppState>, Auth(user): Auth) -> ApiResult<api::MeResponse> {
    let household = state.households.of(&user).await?.map(household_dto);
    Ok(Json(api::MeResponse {
        username: user.username,
        household,
    }))
}

async fn create_household(
    State(state): State<AppState>,
    Auth(user): Auth,
    body: Result<Json<api::CreateHousehold>, JsonRejection>,
) -> ApiResult<api::HouseholdDto> {
    let Json(request) = body?;
    let household = state.households.create(&user, &request.name).await?;
    Ok(Json(household_dto(household)))
}

async fn join_household(
    State(state): State<AppState>,
    Auth(user): Auth,
    body: Result<Json<api::JoinHousehold>, JsonRejection>,
) -> ApiResult<api::HouseholdDto> {
    let Json(request) = body?;
    let household = state.households.join(&user, &request.invite_code).await?;
    Ok(Json(household_dto(household)))
}

async fn push(
    State(state): State<AppState>,
    Auth(user): Auth,
    body: Result<Json<api::PushRequest>, JsonRejection>,
) -> ApiResult<api::PushResponse> {
    let Json(request) = body?;
    let records: Vec<SyncRecord> = request
        .records
        .into_iter()
        .map(|r| SyncRecord {
            kind: kind_from_dto(r.kind),
            id: r.id,
            updated_at: r.updated_at,
            deleted: r.deleted,
            payload: r.payload,
        })
        .collect();
    let accepted = state.sync.push(&user, &records).await?;
    Ok(Json(api::PushResponse { accepted }))
}

async fn pull(
    State(state): State<AppState>,
    Auth(user): Auth,
    query: Result<Query<api::PullQuery>, QueryRejection>,
) -> ApiResult<api::PullResponse> {
    let Query(query) = query?;
    let page = state.sync.pull(&user, query.cursor).await?;
    Ok(Json(api::PullResponse {
        cursor: page.cursor,
        records: page
            .records
            .into_iter()
            .map(|r| api::SyncRecordDto {
                kind: kind_to_dto(r.kind),
                id: r.id,
                updated_at: r.updated_at,
                deleted: r.deleted,
                payload: r.payload,
            })
            .collect(),
    }))
}
