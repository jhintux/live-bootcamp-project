use std::collections::HashMap;

use crate::domain::{Email, Password, User, UserStore, UserStoreError};

#[derive(Default)]
pub struct HashmapUserStore {
    users: HashMap<Email, User>,
}

#[async_trait::async_trait]
impl UserStore for HashmapUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        if self.users.contains_key(&user.email) {
            return Err(UserStoreError::UserAlreadyExists);
        }
        self.users.insert(user.email.clone(), user);
        Ok(())
    }

    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        match self.users.get(email) {
            Some(user) => Ok(user.clone()),
            None => Err(UserStoreError::UserNotFound),
        }
    }

    async fn validate_user(
        &self,
        email: &Email,
        password: &Password,
    ) -> Result<(), UserStoreError> {
        let user = self.get_user(email).await?;
        if user.password != *password {
            return Err(UserStoreError::InvalidCredentials);
        }
        Ok(())
    }
}

// TODO: Add unit tests for your `HashmapUserStore` implementation
#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::Secret;

    #[tokio::test]
    async fn test_add_user() {
        let mut user_store = HashmapUserStore::default();
        let user = User::new(
            Email::parse(Secret::new("test@test.com".to_string())).unwrap(),
            Password::parse(Secret::new("password".to_string())).unwrap(),
            false,
        );
        user_store.add_user(user).await.unwrap();
    }

    #[tokio::test]
    async fn test_get_user() {
        let mut user_store = HashmapUserStore::default();
        let user = User::new(
            Email::parse(Secret::new("test@test.com".to_string())).unwrap(),
            Password::parse(Secret::new("password".to_string())).unwrap(),
            false,
        );
        user_store.add_user(user).await.unwrap();
        user_store
            .get_user(&Email::parse(Secret::new("test@test.com".to_string())).unwrap())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_validate_user() {
        let mut user_store = HashmapUserStore::default();
        let user = User::new(
            Email::parse(Secret::new("test@test.com".to_string())).unwrap(),
            Password::parse(Secret::new("password".to_string())).unwrap(),
            false,
        );
        user_store.add_user(user).await.unwrap();
        user_store
            .validate_user(
                &Email::parse(Secret::new("test@test.com".to_string())).unwrap(),
                &Password::parse(Secret::new("password".to_string())).unwrap(),
            )
            .await
            .unwrap();
    }
}
