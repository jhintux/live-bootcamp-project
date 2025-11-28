use std::collections::HashSet;

use secrecy::{ExposeSecret,Secret};

use crate::domain::{BannedTokenStore, BannedTokenStoreError};

#[derive(Default)]
pub struct HashsetBannedTokenStore {
    tokens: HashSet<String>,
}

#[async_trait::async_trait]
impl BannedTokenStore for HashsetBannedTokenStore {
    async fn add_banned_token(&mut self, token: Secret<String>) -> Result<(), BannedTokenStoreError> {
        if self.tokens.contains(token.expose_secret()) {
            return Err(BannedTokenStoreError::TokenAlreadyBanned);
        }
        self.tokens.insert(token.expose_secret().to_owned());
        Ok(())
    }
    
    async fn is_banned(&self, token: &Secret<String>) -> Result<bool, BannedTokenStoreError> {
        Ok(self.tokens.contains(token.expose_secret()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_banned_token() {
        let mut banned_token_store = HashsetBannedTokenStore::default();
        banned_token_store.add_banned_token(Secret::new("test_token".to_string())).await.unwrap();
        assert!(banned_token_store.is_banned(&Secret::new("test_token".to_string())).await.unwrap());
    }

    #[tokio::test]
    async fn test_is_banned() {
        let mut banned_token_store = HashsetBannedTokenStore::default();
        banned_token_store.add_banned_token(Secret::new("test_token".to_string())).await.unwrap();
        assert!(banned_token_store.is_banned(&Secret::new("test_token".to_string())).await.unwrap());
    }
}