use axum::{extract::{Json, State}, http::StatusCode, response::IntoResponse};

use serde::{Deserialize, Serialize};

use crate::{app_state::AppState, domain::AuthAPIError, utils::validate_token};

pub async fn verify_token(
    State(app_state): State<AppState>,
    body: Json<VerifyTokenBody>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let banned_token_store = app_state.banned_token_store.read().await;
    match validate_token(&*banned_token_store, &body.token).await {
        Ok(_) => Ok(StatusCode::OK),
        Err(_) => Err(AuthAPIError::InvalidToken),
    }
}

#[derive(Serialize, Deserialize)]
pub struct VerifyTokenBody {
    pub token: String,
}
