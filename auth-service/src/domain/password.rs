use sqlx::Type;
use color_eyre::eyre::{eyre, Result};

#[derive(Hash, Eq, PartialEq, Clone, Type)]
#[sqlx(transparent)]
pub struct Password(String);

impl Password {
    pub fn parse(password: &str) -> Result<Password> {
        if password.is_empty() || password.len() < 8 {
            return Err(eyre!("Invalid password"));
        }
        Ok(Password(password.to_owned()))
    }
}

impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        &self.0
    }
}