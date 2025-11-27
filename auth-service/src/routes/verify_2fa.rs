use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, LoginAttemptId, TwoFACode},
    utils::generate_auth_cookie,
};
use axum::{
    extract::{Json, State},
    response::IntoResponse,
};
use axum_extra::extract::CookieJar;
use color_eyre::eyre::Result;
use serde::Deserialize;

#[tracing::instrument(name = "Verify 2FA", skip_all)]
pub async fn verify_2fa(
    State(app_state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<Verify2FARequest>,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let email = match Email::parse(&request.email) {
        Ok(email) => email,
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials)),
    };
    let login_attempt_id = match LoginAttemptId::parse(&request.login_attempt_id) {
        Ok(login_attempt_id) => login_attempt_id,
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials)),
    };
    let two_fa_code = match TwoFACode::parse(&request.two_fa_code) {
        Ok(two_fa_code) => two_fa_code,
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials)),
    };

    let mut two_fa_code_store = app_state.two_fa_code_store.write().await;

    let code_tuple = match two_fa_code_store.get_code(&email).await {
        Ok(code_tuple) => code_tuple,
        Err(_) => return (jar, Err(AuthAPIError::IncorrectCredentials)),
    };

    if code_tuple.0 != login_attempt_id || code_tuple.1 != two_fa_code {
        return (jar, Err(AuthAPIError::IncorrectCredentials));
    }

    match two_fa_code_store.remove_code(&email).await {
        Ok(_) => (),
        Err(e) => return (jar, Err(AuthAPIError::UnexpectedError(e.into()))),
    }

    let auth_cookie = match generate_auth_cookie(&email) {
        Ok(cookie) => cookie,
        Err(e) => return (jar, Err(AuthAPIError::UnexpectedError(e.into()))),
    };

    let updated_jar = jar.add(auth_cookie);

    (updated_jar, Ok(()))
}

#[derive(Deserialize)]
pub struct Verify2FARequest {
    pub email: String,
    pub login_attempt_id: String,
    #[serde(rename = "2FACode")]
    pub two_fa_code: String,
}
