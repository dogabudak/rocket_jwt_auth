use jsonwebtoken::{encode, EncodingKey, Header};
use rocket::http::{Header as RocketHeader, Status};
use rocket::local::asynchronous::Client;
use rocket::{get, routes};
use rocket_jwt_auth::Token;
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

const TEST_SECRET: &str = "test-secret-key-for-jwt";

#[derive(Serialize)]
struct Claims {
    sub: String,
    exp: usize,
    iat: usize,
}

fn now() -> usize {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize
}

fn make_token(sub: &str, exp: usize, iat: usize, secret: &str) -> String {
    let claims = Claims {
        sub: sub.to_string(),
        exp,
        iat,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .unwrap()
}

#[get("/protected")]
fn protected(token: Token) -> String {
    format!("hello {}", token.sub)
}

async fn build_client() -> Client {
    let rocket = rocket::build().mount("/", routes![protected]);
    Client::tracked(rocket).await.unwrap()
}

#[rocket::async_test]
async fn test_valid_token_returns_200() {
    // SAFETY: tests run with --test-threads=1 so no concurrent env access.
    unsafe { std::env::set_var("JWT_SECRET", TEST_SECRET) };
    let client = build_client().await;

    let token = make_token("user-42", now() + 3600, now(), TEST_SECRET);
    let response = client
        .get("/protected")
        .header(RocketHeader::new("Authorization", format!("Bearer {token}")))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);
    let body = response.into_string().await.unwrap();
    assert_eq!(body, "hello user-42");
}

#[rocket::async_test]
async fn test_missing_authorization_header_returns_401() {
    // SAFETY: tests run with --test-threads=1 so no concurrent env access.
    unsafe { std::env::set_var("JWT_SECRET", TEST_SECRET) };
    let client = build_client().await;

    let response = client.get("/protected").dispatch().await;

    assert_eq!(response.status(), Status::Unauthorized);
}

#[rocket::async_test]
async fn test_invalid_format_not_bearer_returns_401() {
    // SAFETY: tests run with --test-threads=1 so no concurrent env access.
    unsafe { std::env::set_var("JWT_SECRET", TEST_SECRET) };
    let client = build_client().await;

    let token = make_token("user-1", now() + 3600, now(), TEST_SECRET);
    let response = client
        .get("/protected")
        .header(RocketHeader::new("Authorization", format!("Basic {token}")))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Unauthorized);
}

#[rocket::async_test]
async fn test_expired_token_returns_401() {
    // SAFETY: tests run with --test-threads=1 so no concurrent env access.
    unsafe { std::env::set_var("JWT_SECRET", TEST_SECRET) };
    let client = build_client().await;

    // Token expired 1 hour ago
    let token = make_token("user-1", now() - 3600, now() - 7200, TEST_SECRET);
    let response = client
        .get("/protected")
        .header(RocketHeader::new("Authorization", format!("Bearer {token}")))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Unauthorized);
}

#[rocket::async_test]
async fn test_invalid_signature_returns_401() {
    // SAFETY: tests run with --test-threads=1 so no concurrent env access.
    unsafe { std::env::set_var("JWT_SECRET", TEST_SECRET) };
    let client = build_client().await;

    // Sign with a different secret
    let token = make_token("user-1", now() + 3600, now(), "wrong-secret");
    let response = client
        .get("/protected")
        .header(RocketHeader::new("Authorization", format!("Bearer {token}")))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Unauthorized);
}

#[rocket::async_test]
async fn test_malformed_token_returns_401() {
    // SAFETY: tests run with --test-threads=1 so no concurrent env access.
    unsafe { std::env::set_var("JWT_SECRET", TEST_SECRET) };
    let client = build_client().await;

    let response = client
        .get("/protected")
        .header(RocketHeader::new("Authorization", "Bearer not.a.jwt"))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Unauthorized);
}

#[rocket::async_test]
async fn test_missing_secret_returns_500() {
    // SAFETY: tests run with --test-threads=1 so no concurrent env access.
    unsafe { std::env::remove_var("JWT_SECRET") };
    let client = build_client().await;

    let token = make_token("user-1", now() + 3600, now(), "irrelevant");
    let response = client
        .get("/protected")
        .header(RocketHeader::new("Authorization", format!("Bearer {token}")))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::InternalServerError);
}

#[rocket::async_test]
async fn test_bearer_prefix_is_case_sensitive() {
    // SAFETY: tests run with --test-threads=1 so no concurrent env access.
    unsafe { std::env::set_var("JWT_SECRET", TEST_SECRET) };
    let client = build_client().await;

    let token = make_token("user-1", now() + 3600, now(), TEST_SECRET);
    // "bearer" lowercase should not match "Bearer"
    let response = client
        .get("/protected")
        .header(RocketHeader::new("Authorization", format!("bearer {token}")))
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Unauthorized);
}
