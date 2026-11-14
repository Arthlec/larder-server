//! End-to-end tests of the HTTP API: real router, real use cases, real
//! SQLite (in memory). Only password hashing is turned down for speed.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use larder_api_types::*;
use larder_server::{AppState, router};
use larder_server_infrastructure::{Argon2Hasher, Db};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

async fn app_with(allow_registration: bool) -> Router {
    let db = Db::in_memory().await.unwrap();
    let state = AppState::new(
        db,
        Arc::new(Argon2Hasher::insecure_fast()),
        allow_registration,
    )
    .await
    .unwrap();
    router(state)
}

async fn app() -> Router {
    app_with(true).await
}

async fn call(
    app: &Router,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut request = Request::builder().method(method).uri(path);
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let request = match body {
        Some(json) => request
            .header("content-type", "application/json")
            .body(Body::from(json.to_string()))
            .unwrap(),
        None => request.body(Body::empty()).unwrap(),
    };
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

fn parse<T: DeserializeOwned>(value: Value) -> T {
    serde_json::from_value(value).unwrap()
}

async fn register(app: &Router, name: &str) -> String {
    let (status, body) = call(
        app,
        "POST",
        "/auth/register",
        None,
        Some(json!({"username": name, "password": "longenough"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    parse::<TokenResponse>(body).token
}

async fn create_household(app: &Router, token: &str) -> HouseholdDto {
    let (status, body) = call(
        app,
        "POST",
        "/households",
        Some(token),
        Some(json!({"name": "Home"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    parse(body)
}

fn record(id: Uuid, updated_at: i64) -> Value {
    json!({"kind": "pantry_item", "id": id, "updated_at": updated_at,
           "deleted": false, "payload": format!("{{\"v\":{updated_at}}}")})
}

fn error(body: &Value) -> &str {
    body["error"].as_str().unwrap_or_default()
}

#[tokio::test]
async fn health_needs_no_token() {
    let (status, body) = call(&app().await, "GET", "/health", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(parse::<HealthResponse>(body).status, "ok");
}

#[tokio::test]
async fn register_login_and_me() {
    let app = app().await;
    register(&app, "ana").await;
    let (status, body) = call(
        &app,
        "POST",
        "/auth/login",
        None,
        Some(json!({"username": "Ana", "password": "longenough"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let token = parse::<TokenResponse>(body).token;
    let (status, body) = call(&app, "GET", "/me", Some(&token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        parse::<MeResponse>(body),
        MeResponse {
            username: "ana".into(),
            household: None
        }
    );
}

#[tokio::test]
async fn registration_errors_have_fitting_statuses() {
    let app = app().await;
    register(&app, "ana").await;
    let attempt = |name: &'static str, password: &'static str| {
        let app = app.clone();
        async move {
            call(
                &app,
                "POST",
                "/auth/register",
                None,
                Some(json!({"username": name, "password": password})),
            )
            .await
        }
    };
    let (status, body) = attempt("ana", "longenough").await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error(&body), "this username is taken");
    assert_eq!(attempt("x", "longenough").await.0, StatusCode::BAD_REQUEST);
    assert_eq!(attempt("bob", "short").await.0, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn closed_registration_is_forbidden() {
    let app = app_with(false).await;
    let (status, body) = call(
        &app,
        "POST",
        "/auth/register",
        None,
        Some(json!({"username": "ana", "password": "longenough"})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error(&body), "registration is closed on this server");
}

#[tokio::test]
async fn wrong_password_is_unauthorised_with_a_vague_message() {
    let app = app().await;
    register(&app, "ana").await;
    for (name, password) in [("ana", "wrongpassword"), ("nobody", "longenough")] {
        let (status, body) = call(
            &app,
            "POST",
            "/auth/login",
            None,
            Some(json!({"username": name, "password": password})),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(error(&body), "wrong username or password");
    }
}

#[tokio::test]
async fn protected_routes_reject_missing_or_bad_tokens() {
    let app = app().await;
    for (method, path) in [
        ("GET", "/me"),
        ("POST", "/households"),
        ("POST", "/households/join"),
        ("POST", "/sync/push"),
        ("GET", "/sync/pull"),
    ] {
        for token in [None, Some("garbage")] {
            let (status, body) = call(&app, method, path, token, Some(json!({}))).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {path}");
            assert_eq!(error(&body), "sign in again");
        }
    }
}

#[tokio::test]
async fn malformed_json_is_a_client_error_with_an_error_body() {
    let app = app().await;
    let (status, body) = call(
        &app,
        "POST",
        "/auth/login",
        None,
        Some(json!({"username": 1})),
    )
    .await;
    assert!(status.is_client_error());
    assert!(!error(&body).is_empty());
}

#[tokio::test]
async fn household_create_join_and_me() {
    let app = app().await;
    let ana = register(&app, "ana").await;
    let bob = register(&app, "bob").await;
    let home = create_household(&app, &ana).await;
    assert_eq!(home.name, "Home");

    let (status, body) = call(
        &app,
        "POST",
        "/households/join",
        Some(&bob),
        Some(json!({"invite_code": home.invite_code.to_lowercase()})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(parse::<HouseholdDto>(body), home);

    let (_, body) = call(&app, "GET", "/me", Some(&bob), None).await;
    assert_eq!(parse::<MeResponse>(body).household, Some(home));
}

#[tokio::test]
async fn household_errors() {
    let app = app().await;
    let ana = register(&app, "ana").await;
    let (status, _) = call(
        &app,
        "POST",
        "/households/join",
        Some(&ana),
        Some(json!({"invite_code": "NOPE"})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    create_household(&app, &ana).await;
    let (status, _) = call(
        &app,
        "POST",
        "/households",
        Some(&ana),
        Some(json!({"name": "Two"})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) = call(
        &app,
        "POST",
        "/households",
        Some(&ana),
        Some(json!({"name": ""})),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "membership is checked before the name"
    );
}

#[tokio::test]
async fn sync_without_household_is_a_conflict() {
    let app = app().await;
    let ana = register(&app, "ana").await;
    let (status, body) = call(&app, "GET", "/sync/pull", Some(&ana), None).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error(&body), "create or join a household first");
}

#[tokio::test]
async fn two_members_sync_through_the_server() {
    let app = app().await;
    let ana = register(&app, "ana").await;
    let bob = register(&app, "bob").await;
    let home = create_household(&app, &ana).await;
    call(
        &app,
        "POST",
        "/households/join",
        Some(&bob),
        Some(json!({"invite_code": home.invite_code})),
    )
    .await;

    let (milk, eggs) = (Uuid::new_v4(), Uuid::new_v4());
    let (status, body) = call(
        &app,
        "POST",
        "/sync/push",
        Some(&ana),
        Some(json!({"records": [record(milk, 10), record(eggs, 11)]})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(parse::<PushResponse>(body).accepted, 2);

    // Bob receives both.
    let (_, body) = call(&app, "GET", "/sync/pull?cursor=0", Some(&bob), None).await;
    let page: PullResponse = parse(body);
    assert_eq!(page.records.len(), 2);
    assert_eq!(page.records[0].id, milk);
    assert_eq!(page.records[0].kind, EntityKind::PantryItem);
    let cursor = page.cursor;

    // Bob deletes the milk; an older edit from Ana must not bring it back.
    let tombstone = json!({"kind": "pantry_item", "id": milk, "updated_at": 30,
                           "deleted": true, "payload": ""});
    call(
        &app,
        "POST",
        "/sync/push",
        Some(&bob),
        Some(json!({"records": [tombstone]})),
    )
    .await;
    let (_, body) = call(
        &app,
        "POST",
        "/sync/push",
        Some(&ana),
        Some(json!({"records": [record(milk, 20)]})),
    )
    .await;
    assert_eq!(parse::<PushResponse>(body).accepted, 0);

    // Ana sees only the change made since her cursor: the deletion.
    let (_, body) = call(
        &app,
        "GET",
        &format!("/sync/pull?cursor={cursor}"),
        Some(&ana),
        None,
    )
    .await;
    let page: PullResponse = parse(body);
    assert_eq!(page.records.len(), 1);
    assert!(page.records[0].deleted);
    assert_eq!(page.records[0].id, milk);

    // Nothing new afterwards, and the cursor does not move.
    let (_, body) = call(
        &app,
        "GET",
        &format!("/sync/pull?cursor={}", page.cursor),
        Some(&ana),
        None,
    )
    .await;
    let empty: PullResponse = parse(body);
    assert!(empty.records.is_empty());
    assert_eq!(empty.cursor, page.cursor);
}

#[tokio::test]
async fn another_household_cannot_read_the_data() {
    let app = app().await;
    let ana = register(&app, "ana").await;
    let eve = register(&app, "eve").await;
    create_household(&app, &ana).await;
    create_household(&app, &eve).await;
    call(
        &app,
        "POST",
        "/sync/push",
        Some(&ana),
        Some(json!({"records": [record(Uuid::new_v4(), 10)]})),
    )
    .await;
    let (_, body) = call(&app, "GET", "/sync/pull", Some(&eve), None).await;
    assert!(parse::<PullResponse>(body).records.is_empty());
}

#[tokio::test]
async fn invalid_push_is_rejected() {
    let app = app().await;
    let ana = register(&app, "ana").await;
    create_household(&app, &ana).await;
    let no_payload = json!({"kind": "recipe", "id": Uuid::new_v4(), "updated_at": 1,
                            "deleted": false, "payload": ""});
    let (status, _) = call(
        &app,
        "POST",
        "/sync/push",
        Some(&ana),
        Some(json!({"records": [no_payload]})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let bad_kind = json!({"kind": "user", "id": Uuid::new_v4(), "updated_at": 1,
                          "deleted": false, "payload": "{}"});
    let (status, _) = call(
        &app,
        "POST",
        "/sync/push",
        Some(&ana),
        Some(json!({"records": [bad_kind]})),
    )
    .await;
    assert!(status.is_client_error());
    let (status, _) = call(&app, "GET", "/sync/pull?cursor=abc", Some(&ana), None).await;
    assert!(status.is_client_error());
}
