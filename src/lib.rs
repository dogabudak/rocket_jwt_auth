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

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Token {
    type Error = TokenError;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let header = match request.headers().get_one("Authorization") {
            Some(h) => h,
            None => return request::Outcome::Error((Status::Unauthorized, TokenError::MissingHeader)),
        };

        let token_str = match header.strip_prefix("Bearer ") {
            Some(t) => t,
            None => return request::Outcome::Error((Status::Unauthorized, TokenError::InvalidFormat)),
        };

        let secret = match std::env::var("JWT_SECRET") {
            Ok(s) => s,
            Err(_) => return request::Outcome::Error((Status::InternalServerError, TokenError::MissingSecret)),
        };

        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;

        match decode::<Token>(token_str, &DecodingKey::from_secret(secret.as_bytes()), &validation) {
            Ok(data) => request::Outcome::Success(data.claims),
            Err(e) => {
                if e.kind() == &jsonwebtoken::errors::ErrorKind::ExpiredSignature {
                    request::Outcome::Error((Status::Unauthorized, TokenError::Expired))
                } else {
                    request::Outcome::Error((Status::Unauthorized, TokenError::InvalidToken(e.to_string())))
                }
            }
        }
    }
}
