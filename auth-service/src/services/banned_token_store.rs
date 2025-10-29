use std::collections::HashSet;

use crate::domain::{BannedTokenStore, BannedTokenStoreError};

#[derive(Default)]
pub struct HashsetBannedTokenStore {
    tokens: HashSet<String>,
}

#[async_trait::async_trait]
impl BannedTokenStore for HashsetBannedTokenStore {
    
    async fn add_banned_token(&mut self, token: String) -> Result<(), BannedTokenStoreError> {
        if self.tokens.contains(&token) {
            return Err(BannedTokenStoreError::TokenAlreadyBanned);
        }
        self.tokens.insert(token);
        Ok(())
    }
    
    async fn is_banned(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
        Ok(self.tokens.contains(token))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_banned_token() {
        let mut banned_token_store = HashsetBannedTokenStore::default();
        banned_token_store.add_banned_token("test_token".to_string()).await.unwrap();
        assert!(banned_token_store.is_banned("test_token").await.unwrap());
    }

    #[tokio::test]
    async fn test_is_banned() {
        let mut banned_token_store = HashsetBannedTokenStore::default();
        banned_token_store.add_banned_token("test_token".to_string()).await.unwrap();
        assert!(banned_token_store.is_banned("test_token").await.unwrap());
    }
}