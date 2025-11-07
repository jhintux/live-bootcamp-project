use std::error::Error;

use argon2::{
    password_hash::SaltString, Algorithm, Argon2, Params, PasswordHash, PasswordHasher,
    PasswordVerifier, Version,
};

use sqlx::PgPool;

use crate::domain::{Email, Password, User, UserStore, UserStoreError};

pub struct PostgresUserStore {
    pool: PgPool,
}

impl PostgresUserStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl UserStore for PostgresUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        let password_hash = compute_password_hash(user.password.as_ref().to_owned())
            .await
            .map_err(|_| UserStoreError::UnexpectedError)?;
        let query = "INSERT INTO users (email, password_hash, requires_2fa) VALUES ($1, $2, $3)";
        sqlx::query(query)
            .bind(user.email.as_ref().to_owned())
            .bind(password_hash)
            .bind(user.requires_2fa)
            .execute(&self.pool)
            .await
            .map_err(|_| UserStoreError::UnexpectedError)?;
        Ok(())
    }

    async fn get_user<'a>(&'a self, email: &Email) -> Result<&'a User, UserStoreError> {
        let query = "SELECT email, password_hash, requires_2fa FROM users WHERE email = $1";
        let result = sqlx::query_as::<_, User>(query)
            .bind(email.as_ref().to_owned())
            .fetch_optional(&self.pool)
            .await.map_err(|_| UserStoreError::UnexpectedError)?;
        if result.is_none() {
            return Err(UserStoreError::UserNotFound);
        }

        let user = result.unwrap();
        // NOTE: We need to return an owned User, not a reference to a temporary.
        // The function signature must be changed to `Result<User, UserStoreError>`
        Ok(Box::leak(Box::new(user)))
    }

    async fn validate_user(
        &self,
        email: &Email,
        password: &Password,
    ) -> Result<(), UserStoreError> {
        let user = self.get_user(email).await;
        if user.is_err() {
            return Err(UserStoreError::UserNotFound);
        }
        let user = user.unwrap();
        verify_password_hash(
            user.password.as_ref().to_owned(),
            password.as_ref().to_owned(),
        )
        .await
        .map_err(|_| UserStoreError::UnexpectedError)?;
        Ok(())
    }
}

// Helper function to verify if a given password matches an expected hash
// TODO: Hashing is a CPU-intensive operation. To avoid blocking
// other async tasks, update this function to perform hashing on a
// separate thread pool using tokio::task::spawn_blocking. Note that you
// will need to update the input parameters to be String types instead of &str
async fn verify_password_hash(
    expected_password_hash: String,
    password_candidate: String,
) -> Result<(), Box<dyn Error>> {
    tokio::task::spawn_blocking(move || -> Result<(), Box<dyn Error + Send>> {
        let expected_password_hash: PasswordHash<'_> =
            PasswordHash::new(&expected_password_hash)
                .map_err(|e| Box::new(e) as Box<dyn Error + Send>)?;

        Argon2::default()
            .verify_password(password_candidate.as_bytes(), &expected_password_hash)
            .map_err(|e| Box::new(e) as Box<dyn Error + Send>)
    })
    .await
    .map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::Other, e)) as Box<dyn Error>)?
    .map_err(|e| e as Box<dyn Error>)
}

// Helper function to hash passwords before persisting them in the database.
// Uses tokio::task::spawn_blocking to perform CPU-intensive hashing on a
// separate thread pool to avoid blocking other async tasks.
async fn compute_password_hash(password: String) -> Result<String, Box<dyn Error>> {
    tokio::task::spawn_blocking(move || -> Result<String, Box<dyn Error + Send>> {
        let salt: SaltString = SaltString::generate(&mut rand::thread_rng());
        let password_hash = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(15000, 2, 1, None).map_err(|e| Box::new(e) as Box<dyn Error + Send>)?,
        )
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| Box::new(e) as Box<dyn Error + Send>)?
        .to_string();

        Ok(password_hash)
    })
    .await
    .map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::Other, e)) as Box<dyn Error>)?
    .map_err(|e| e as Box<dyn Error>)
}
