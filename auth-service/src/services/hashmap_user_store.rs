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

    async fn get_user<'a>(&'a self, email: &Email) -> Result<&'a User, UserStoreError> {
        self.users.get(email).ok_or(UserStoreError::UserNotFound)
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

    #[tokio::test]
    async fn test_add_user() {
        let mut user_store = HashmapUserStore::default();
        let user = User::new(
            Email::parse("test@test.com").unwrap(),
            Password::parse("password").unwrap(),
            false,
        );
        user_store.add_user(user).await.unwrap();
    }

    #[tokio::test]
    async fn test_get_user() {
        let mut user_store = HashmapUserStore::default();
        let user = User::new(
            Email::parse("test@test.com").unwrap(),
            Password::parse("password").unwrap(),
            false,
        );
        user_store.add_user(user).await.unwrap();
        user_store
            .get_user(&Email::parse("test@test.com").unwrap())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_validate_user() {
        let mut user_store = HashmapUserStore::default();
        let user = User::new(
            Email::parse("test@test.com").unwrap(),
            Password::parse("password").unwrap(),
            false,
        );
        user_store.add_user(user).await.unwrap();
        user_store
            .validate_user(
                &Email::parse("test@test.com").unwrap(),
                &Password::parse("password").unwrap(),
            )
            .await
            .unwrap();
    }
}
