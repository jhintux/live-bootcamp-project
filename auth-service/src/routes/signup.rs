use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize,Serialize};

use crate::{app_state::AppState, domain::{AuthAPIError, Email, Password, User}};

#[tracing::instrument(name = "Signup", skip_all)]
pub async fn signup(
    State(app_state): State<AppState>, 
    Json(request): Json<SignupRequest>
) -> Result<impl IntoResponse, AuthAPIError> {
    let email = Email::parse(&request.email).map_err(|_| AuthAPIError::InvalidCredentials)?;
    let password = Password::parse(&request.password).map_err(|_| AuthAPIError::InvalidCredentials)?;

    let user = User::new(email, password, request.requires_2fa);
    let mut user_store = app_state.user_store.write().await;

    if let Err(e) = user_store.add_user(user).await {
        return Err(AuthAPIError::UnexpectedError(e.into())); // Updated!
    }

    Ok((StatusCode::CREATED, Json(SignupResponse {
        message: "User created successfully!".to_string(),
    })))
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