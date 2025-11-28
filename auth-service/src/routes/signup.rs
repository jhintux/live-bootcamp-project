use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize,Serialize};
use secrecy::Secret;

use crate::{app_state::AppState, domain::{AuthAPIError, Email, Password, User}};

pub async fn signup(
    State(app_state): State<AppState>, 
    Json(request): Json<SignupRequest>
) -> Result<impl IntoResponse, AuthAPIError> {
    let email = Email::parse(request.email).map_err(|_| AuthAPIError::InvalidCredentials)?;
    let password = Password::parse(request.password).map_err(|_| AuthAPIError::InvalidCredentials)?;

    let user = User::new(email, password, request.requires_2fa);
    let mut user_store = app_state.user_store.write().await;

    match user_store.add_user(user).await {
        Ok(_) => Ok((StatusCode::CREATED, Json(SignupResponse {
            message: "User created successfully!".to_string(),
        }))),
        Err(_) => Err(AuthAPIError::UserAlreadyExists),
    }
}

#[derive(Deserialize)]
pub struct SignupRequest {
    pub email: Secret<String>,
    pub password: Secret<String>,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct SignupResponse {
    pub message: String,
}