use jsonwebtoken::{DecodingKey, Validation, Algorithm, decode};
use rocket::http::Status;
use rocket::request::{self, FromRequest, Request};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Decoded JWT claims extracted from a valid Bearer token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    pub sub: String,
    pub exp: usize,
    pub iat: usize,
}

/// Errors that can occur during JWT authentication.
#[derive(Debug)]
pub enum TokenError {
    /// No `Authorization` header present.
    MissingHeader,
    /// Header value does not start with `Bearer `.
    InvalidFormat,
    /// Token signature is valid but the token has expired.
    Expired,
    /// Token is malformed or has an invalid signature.
    InvalidToken(String),
    /// The `JWT_SECRET` environment variable is not set.
    MissingSecret,
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenError::MissingHeader => write!(f, "Missing Authorization header"),
            TokenError::InvalidFormat => write!(f, "Invalid format: expected Bearer token"),
            TokenError::Expired => write!(f, "Token has expired"),
            TokenError::InvalidToken(msg) => write!(f, "Invalid token: {msg}"),
            TokenError::MissingSecret => write!(f, "JWT_SECRET environment variable not set"),
        }
    }
}

impl std::error::Error for TokenError {}

/// Returns early from `from_request` with an `Outcome::Error`.
///
/// `fail!(Unauthorized, MissingHeader)` expands to
/// `return request::Outcome::Error((Status::Unauthorized, TokenError::MissingHeader))`.
/// A function could not do this: only a macro can `return` from its caller.
macro_rules! fail {
    // Tuple variant: fail!(Unauthorized, InvalidToken(e.to_string()))
    ($status:ident, $variant:ident ( $($arg:expr),* )) => {
        return request::Outcome::Error((Status::$status, TokenError::$variant($($arg),*)))
    };
    // Unit variant: fail!(Unauthorized, MissingHeader)
    ($status:ident, $variant:ident) => {
        return request::Outcome::Error((Status::$status, TokenError::$variant))
    };
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Token {
    type Error = TokenError;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let Some(header) = request.headers().get_one("Authorization") else {
            fail!(Unauthorized, MissingHeader);
        };

        let Some(token_str) = header.strip_prefix("Bearer ") else {
            fail!(Unauthorized, InvalidFormat);
        };

        let Ok(secret) = std::env::var("JWT_SECRET") else {
            fail!(InternalServerError, MissingSecret);
        };

        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;

        match decode::<Token>(token_str, &DecodingKey::from_secret(secret.as_bytes()), &validation) {
            Ok(data) => request::Outcome::Success(data.claims),
            Err(e) if e.kind() == &jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                fail!(Unauthorized, Expired)
            }
            Err(e) => fail!(Unauthorized, InvalidToken(e.to_string())),
        }
    }
}
