use crate::helpers::TestApp;
use auth_service::{domain::Email, utils::generate_auth_token};

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;

    let malformed_input = serde_json::json!({});

    let response = app.post_verify_token(&malformed_input).await;

    assert_eq!(response.status().as_u16(), 422);
    
    app.clean_up().await;
}
#[tokio::test]
async fn should_return_200_valid_token() {
    let app = TestApp::new().await;

    let valid_token = generate_auth_token(&Email::parse("test@example.com").unwrap()).unwrap();

    let response = app.post_verify_token(&serde_json::json!({ "token": valid_token })).await;

    assert_eq!(response.status().as_u16(), 200);
    
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let app = TestApp::new().await;

    let invalid_token = "invalid_token".to_owned();

    let response = app.post_verify_token(&serde_json::json!({ "token": invalid_token })).await;

    assert_eq!(response.status().as_u16(), 401);
    
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_banned_token() {
    let app = TestApp::new().await;

    let valid_token = generate_auth_token(&Email::parse("test@example.com").unwrap()).unwrap();
    
    // Ban the token
    app.banned_token_store.write().await.add_banned_token(valid_token.clone()).await.unwrap();

    let response = app.post_verify_token(&serde_json::json!({ "token": valid_token })).await;

    assert_eq!(response.status().as_u16(), 401);
    
    app.clean_up().await;
}