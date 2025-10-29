use std::collections::HashMap;

use crate::domain::{Email, LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError};

#[derive(Default)]
pub struct HashmapTwoFACodeStore {
    codes: HashMap<Email, (LoginAttemptId, TwoFACode)>,
}

#[async_trait::async_trait]
impl TwoFACodeStore for HashmapTwoFACodeStore {
    async fn add_code(&mut self, email: Email, login_attempt_id: LoginAttemptId, code: TwoFACode) -> Result<(), TwoFACodeStoreError> {
        self.codes.insert(email, (login_attempt_id, code));
        Ok(())
    }

    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        self.codes.remove(email);
        Ok(())
    }

    async fn get_code(&self, email: &Email) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        let (login_attempt_id, code) = self.codes.get(email).ok_or(TwoFACodeStoreError::LoginAttemptIdNotFound)?;
        Ok((login_attempt_id.clone(), code.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_code() {
        let mut two_fa_code_store = HashmapTwoFACodeStore::default();
        let email = Email::parse("test@test.com").unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::default();
        two_fa_code_store.add_code(email, login_attempt_id, code).await.unwrap();
    }

    #[tokio::test]
    async fn test_remove_code() {
        let mut two_fa_code_store = HashmapTwoFACodeStore::default();
        let email = Email::parse("test@test.com").unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::default();
        two_fa_code_store.add_code(email.clone(), login_attempt_id, code).await.unwrap();
        two_fa_code_store.remove_code(&email).await.unwrap();
        assert!(two_fa_code_store.get_code(&email).await.is_err());
    }

    #[tokio::test]
    async fn test_get_code() {
        let mut two_fa_code_store = HashmapTwoFACodeStore::default();
        let email = Email::parse("test@test.com").unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::default();
        two_fa_code_store.add_code(email.clone(), login_attempt_id, code).await.unwrap();
        let (login_attempt_id, code) = two_fa_code_store.get_code(&email).await.unwrap();
        assert_eq!(login_attempt_id, login_attempt_id);
        assert_eq!(code, code);
    }
}
