use auth_service::{domain::Email, utils::{JWT_COOKIE_NAME, generate_auth_token}, ErrorResponse};
use reqwest::Url;
use secrecy::{ExposeSecret, Secret};

use crate::helpers::TestApp;

#[tokio::test]
async fn should_return_400_if_jwt_cookie_missing() {
    let app = TestApp::new().await;
    let response = app.post_logout().await;

    assert_eq!(response.status().as_u16(), 400);
    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "Missing token".to_owned()
    );
    
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let app = TestApp::new().await;

    // add invalid cookie
    app.cookie_jar.add_cookie_str(
        &format!(
            "{}=invalid; HttpOnly; SameSite=Lax; Secure; Path=/",
            JWT_COOKIE_NAME
        ),
        &Url::parse("http://127.0.0.1").expect("Failed to parse URL"),
    );

    let response = app.post_logout().await;

    assert_eq!(response.status().as_u16(), 401);

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "Invalid token".to_owned()
    );
    
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_200_if_valid_jwt_cookie() {
    let app = TestApp::new().await;

    let token = generate_auth_token(&Email::parse(Secret::new("test@example.com".to_string())).unwrap()).unwrap();
    app.cookie_jar.add_cookie_str(
        &format!(
            "{}={}; HttpOnly; SameSite=Lax; Secure; Path=/",
            JWT_COOKIE_NAME, token.expose_secret().to_owned()
        ),
        &Url::parse("http://127.0.0.1").expect("Failed to parse URL"),
    );

    let response = app.post_logout().await;

    let banned_token_store = app.banned_token_store.read().await;
    assert!(banned_token_store.is_banned(&token).await.unwrap());

    assert_eq!(response.status().as_u16(), 200);
    
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_400_if_logout_called_twice_in_a_row() {
    let app = TestApp::new().await;

    // Add valid JWT cookie
    app.cookie_jar.add_cookie_str(
        &format!(
            "{}={}; HttpOnly; SameSite=Lax; Secure; Path=/",
            JWT_COOKIE_NAME, generate_auth_token(&Email::parse(Secret::new("test@example.com".to_string())).unwrap()).unwrap().expose_secret()
        ),
        &Url::parse("http://127.0.0.1").expect("Failed to parse URL"),
    );

    // First logout should succeed
    let response = app.post_logout().await;
    assert_eq!(response.status().as_u16(), 200);

    // Second logout should fail since cookie is now cleared
    let response = app.post_logout().await;
    assert_eq!(response.status().as_u16(), 400);
    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "Missing token".to_owned()
    );
    
    app.clean_up().await;
}
