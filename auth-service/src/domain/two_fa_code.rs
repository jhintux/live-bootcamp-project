use rand::prelude::*;
use color_eyre::eyre::{Context, Result};

#[derive(Clone, Debug, PartialEq)]
pub struct TwoFACode(String);

impl TwoFACode {
    pub fn parse(code: &str) -> Result<Self> {
        let code_as_u32 = code.parse::<u32>().wrap_err("Invalid 2FA code")?;
        Ok(TwoFACode(code_as_u32.to_string()))
    }
}

impl Default for TwoFACode {
    fn default() -> Self {
        let mut rng = rand::thread_rng();
        let code = format!("{:06}", rng.gen_range(0..=999_999));
        TwoFACode(code)
    }
}

impl AsRef<str> for TwoFACode {
    fn as_ref(&self) -> &str {
        &self.0
    }
}