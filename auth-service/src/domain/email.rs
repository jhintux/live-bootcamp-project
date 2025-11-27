use validator::validate_email;
use sqlx::Type;
use color_eyre::eyre::{eyre, Result};

#[derive(Hash, Eq, PartialEq, Clone, Type)]
#[sqlx(transparent)]
pub struct Email(String);

impl Email {
    pub fn parse(email: &str) -> Result<Email> {
        if !validate_email(email) {
            return Err(eyre!("Invalid email"));
        }
        Ok(Email(email.to_owned()))
    }
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        &self.0
    }
}