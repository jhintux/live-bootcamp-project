use sqlx::Type;

#[derive(Hash, Eq, PartialEq, Type)]
#[sqlx(transparent)]
pub struct Password(String);

impl Password {
    pub fn parse(password: &str) -> Result<Password, String> {
        if password.is_empty() || password.len() < 8 {
            return Err("Invalid password".to_string());
        }
        Ok(Password(password.to_owned()))
    }
}

impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        &self.0
    }
}