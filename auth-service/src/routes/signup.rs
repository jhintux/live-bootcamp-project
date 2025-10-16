use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize,Serialize};

use crate::{app_state::AppState, domain::{AuthAPIError, User}};

pub async fn signup(
    State(app_state): State<AppState>, 
    Json(request): Json<SignupRequest>
) -> Result<impl IntoResponse, AuthAPIError> {
    let email = request.email;
    let password = request.password;
    
    if email.is_empty() || !email.contains('@') {
        return Err(AuthAPIError::InvalidCredentials);
    }

    if password.is_empty() || password.len() < 8 {
        return Err(AuthAPIError::InvalidCredentials);
    }

    let user = User::new(email, password, request.requires_2fa);
    let mut user_store = app_state.user_store.write().await;

    match user_store.add_user(user) {
        Ok(_) => Ok((StatusCode::CREATED, Json(SignupResponse {
            message: "User created successfully!".to_string(),
        }))),
        Err(_) => Err(AuthAPIError::UserAlreadyExists),
    }
}

#[derive(Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct SignupResponse {
    pub message: String,
}