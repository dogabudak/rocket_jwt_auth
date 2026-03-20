# rocket_jwt_auth

[![Crates.io](https://img.shields.io/crates/v/rocket_jwt_auth.svg)](https://crates.io/crates/rocket_jwt_auth)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](https://opensource.org/licenses/MIT)

JWT Bearer token authentication guard for [Rocket](https://rocket.rs).

## Installation

```toml
[dependencies]
rocket_jwt_auth = "0.1.0"
```

## Setup

Set the `JWT_SECRET` environment variable with your HS256 signing key:

```bash
export JWT_SECRET="your-secret-key"
```

## Usage

Use `Token` as a request guard on any route that requires authentication:

```rust
use rocket::get;
use rocket_jwt_auth::Token;

#[get("/me")]
fn me(token: Token) -> String {
    format!("User ID: {}", token.sub)
}
```

The guard extracts and validates the JWT from the `Authorization: Bearer <token>` header. If the token is valid, the decoded claims are available via the `Token` struct.

## Token Claims

| Field | Type    | Description              |
|-------|---------|--------------------------|
| `sub` | `String`| Subject (user identifier)|
| `exp` | `usize` | Expiration timestamp     |
| `iat` | `usize` | Issued-at timestamp      |

## Error Handling

| Condition                | Status | Error Variant   |
|--------------------------|--------|-----------------|
| No `Authorization` header| 401    | `MissingHeader` |
| Not `Bearer` prefix      | 401    | `InvalidFormat` |
| Token expired            | 401    | `Expired`       |
| Bad signature / malformed| 401    | `InvalidToken`  |
| `JWT_SECRET` not set     | 500    | `MissingSecret` |

## Testing

```bash
cargo test -- --test-threads=1
```

Tests must run single-threaded because they manipulate the `JWT_SECRET` environment variable.
