use color_eyre::eyre::{Context, Result};
use rand::prelude::*;
use secrecy::{ExposeSecret, Secret};

#[derive(Clone, Debug)]
pub struct TwoFACode(Secret<String>);

impl TwoFACode {
    pub fn parse(code: &str) -> Result<Self> {
        let code_as_u32 = code.parse::<u32>().wrap_err("Invalid 2FA code")?;
        Ok(TwoFACode(Secret::new(code_as_u32.to_string())))
    }
}

impl Default for TwoFACode {
    fn default() -> Self {
        let mut rng = rand::thread_rng();
        let code = format!("{:06}", rng.gen_range(0..=999_999));
        TwoFACode(Secret::new(code))
    }
}

impl PartialEq for TwoFACode {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl AsRef<Secret<String>> for TwoFACode {
    fn as_ref(&self) -> &Secret<String> {
        &self.0
    }
}
