use uuid::Uuid;
use color_eyre::eyre::{Context, Result};

#[derive(Debug, Clone, PartialEq)]
pub struct LoginAttemptId(String);

impl LoginAttemptId {
    pub fn parse(id: &str) -> Result<Self> {
        let parsed_id = uuid::Uuid::parse_str(&id).wrap_err("Invalid login attempt id")?;
        Ok(LoginAttemptId(parsed_id.to_string()))
    }
}

impl Default for LoginAttemptId {
    fn default() -> Self {
        LoginAttemptId(Uuid::new_v4().to_string())
    }
}

impl AsRef<str> for LoginAttemptId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
