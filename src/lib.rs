#![feature(decl_macro)]
use rocket::request::{self, Request, FromRequest};
use rocket::Outcome;
use rocket::http::Status;

pub struct Token(pub String, pub String);
#[derive(Debug)]
pub enum TokenError {
    BadCount,
    Invalid,
}
fn evaluate_credentials(credentials: &str) -> Result<(String, String), TokenError> {

    let mut authorize_header =  credentials.split( " ");
    let header_count = authorize_header.clone().count();
    let header_size: i32 = 2;

    if header_count as i32 != header_size {
        return Err(TokenError::BadCount)
    }
    // TODO remove unwraps here
    let _method = authorize_header.next().unwrap();
    let encoded_user_pass = authorize_header.next().unwrap();

    let mut user_info_fields = encoded_user_pass.split(":");
    let user_info_length = user_info_fields.clone().count();
    let user_info_size: i32 = 2;

    if user_info_length as i32 != user_info_size {
        return Err(TokenError::BadCount)
    }
    let user = user_info_fields.next().unwrap();
    let password = user_info_fields.next().unwrap();
    let normalized_user = user.to_lowercase();
    let normalized_password = password.to_lowercase();
    Ok((normalized_user, normalized_password))
}
impl<'a, 'r> FromRequest<'a, 'r> for Token {
    type Error = TokenError;

    fn from_request(request: &'a Request<'r>) -> request::Outcome<Self, Self::Error> {
        let credentials = request.headers().get_one("authorize");
        match credentials {
            Some(credentials) => {
                let validated_token = evaluate_credentials(credentials);
                match validated_token{
                    Ok((username, password)) => Outcome::Success(Token(username, password)),
                    Err(e)=> Outcome::Failure((Status::BadRequest, e))
                }
            },
            None => Outcome::Failure((Status::BadRequest, TokenError::Invalid))
        }
    }
}
