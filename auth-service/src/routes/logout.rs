use axum::{extract::State, http::StatusCode, response::IntoResponse};
use axum_extra::extract::CookieJar;
use color_eyre::eyre::Result;
use secrecy::Secret;

use crate::{
    app_state::AppState, domain::AuthAPIError, utils::{validate_token, JWT_COOKIE_NAME}
};

#[tracing::instrument(name = "Logout", skip_all)]
pub async fn logout(
    State(app_state): State<AppState>,
    jar: CookieJar,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    // Retrieve JWT cookie from the `CookieJar`
    // Return AuthAPIError::MissingToken is the cookie is not found
    let cookie = match jar.get(JWT_COOKIE_NAME) {
        Some(cookie) => cookie,
        None => return (jar, Err(AuthAPIError::MissingToken)),
    };

    let token = cookie.value().to_owned();

    // TODO: Validate JWT token by calling `validate_token` from the auth service.
    // If the token is valid you can ignore the returned claims for now.
    // Return AuthAPIError::InvalidToken is validation fails.
    let mut banned_token_store = app_state.banned_token_store.write().await;
    
    // Validate JWT token structure, expiration, and banned status
    match validate_token(&*banned_token_store, &Secret::new(token.clone())).await {
        Ok(_) => (),
        Err(_) => return (jar, Err(AuthAPIError::InvalidToken)),
    }
    
    // Add token to banned list
    match banned_token_store.add_banned_token(Secret::new(token)).await {
        Ok(_) => (),
        Err(e) => return (jar, Err(AuthAPIError::UnexpectedError(e.into()))),
    }

    let jar = jar.remove(JWT_COOKIE_NAME);

    (jar, Ok(StatusCode::OK))
}
