use validator::validate_email;

#[derive(Hash, Eq, PartialEq, Clone)]
pub struct Email(String);

impl Email {
    pub fn parse(email: &str) -> Result<Email, String> {
        if !validate_email(email) {
            return Err("Invalid email".to_string());
        }
        Ok(Email(email.to_owned()))
    }
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        &self.0
    }
}