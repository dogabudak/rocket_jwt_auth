#![feature(decl_macro)]
#[macro_use] extern crate rocket;

use rocket_jwt_auth::{Token};

#[get("/login")]
fn login(authorize: Token) {
    println!("{} {}", authorize.0, authorize.1);
}

fn main() {
    rocket::ignite().mount("/", routes![login]).launch();
}
