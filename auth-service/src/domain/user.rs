// The User struct should contain 3 fields. email, which is a String; 
// password, which is also a String; and requires_2fa, which is a boolean. 
use super::{Email, Password};
use sqlx::{FromRow};
#[derive(FromRow, Clone)]
pub struct User {
    pub email: Email,
    #[sqlx(rename = "password_hash")]
    pub password: Password,
    pub requires_2fa: bool,
}

impl User {
    pub fn new(email: Email, password: Password, requires_2fa: bool) -> Self {
        Self { email, password, requires_2fa }
    }
}