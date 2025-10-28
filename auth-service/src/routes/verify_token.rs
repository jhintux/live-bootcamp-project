use axum::{extract::Json, http::StatusCode, response::IntoResponse};

use serde::{Deserialize, Serialize};

use crate::{domain::AuthAPIError, utils::validate_token};

pub async fn verify_token(body: Json<VerifyTokenBody>) -> Result<impl IntoResponse, AuthAPIError> {
    match validate_token(&body.token).await {
        Ok(_) => Ok(StatusCode::OK),
        Err(_) => Err(AuthAPIError::InvalidToken),
    }
}

#[derive(Serialize, Deserialize)]
pub struct VerifyTokenBody {
    pub token: String,
}
