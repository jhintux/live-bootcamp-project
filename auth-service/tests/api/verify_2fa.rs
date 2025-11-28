use auth_service::{domain::Email, routes::TwoFactorAuthResponse, utils::JWT_COOKIE_NAME};
use secrecy::{ExposeSecret, Secret};
use crate::helpers::{TestApp, get_random_email};

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;

    let malformed_input = serde_json::json!({});

    let response = app.post_verify_2fa(&malformed_input).await;

    assert_eq!(response.status().as_u16(), 422);
    
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new().await;

    let invalid_input = serde_json::json!({
        "email": "invalid_email",
        "login_attempt_id": "invalid_login_attempt_id",
        "2FACode": "invalid_2fa_code"
    });

    let response = app.post_verify_2fa(&invalid_input).await;

    assert_eq!(response.status().as_u16(), 400);
    
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_old_code() {
    // Call login twice. Then, attempt to call verify-fa with the 2FA code from the first login requet. This should fail. 
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    });
    
    let response = app.post_signup(&signup_body).await;
    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
    });
    
    let response = app.post_login(&login_body).await;
    assert_eq!(response.status().as_u16(), 206);
    
    let json_body = response.json::<TwoFactorAuthResponse>().await.expect("Could not deserialize response body to TwoFactorAuthResponse");
    let login_attempt_id = json_body.login_attempt_id;

    // Second login request should succeed
    let response = app.post_login(&login_body).await;
    assert_eq!(response.status().as_u16(), 206);

    let verify_2fa_body = serde_json::json!({
        "email": random_email,
        "login_attempt_id": login_attempt_id,
        "2FACode": "123456"
    });
    
    let response = app.post_verify_2fa(&verify_2fa_body).await;
    assert_eq!(response.status().as_u16(), 401);
    
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_200_if_correct_code() {
    // Make sure to assert the auth cookie gets set
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    });
    
    let response = app.post_signup(&signup_body).await;
    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
    });
    
    let response = app.post_login(&login_body).await;
    assert_eq!(response.status().as_u16(), 206);
    
    let json_body = response.json::<TwoFactorAuthResponse>().await.expect("Could not deserialize response body to TwoFactorAuthResponse");
    let login_attempt_id = json_body.login_attempt_id;

    let code_tuple = app
        .two_fa_code_store
        .read()
        .await
        .get_code(&Email::parse(Secret::new(random_email.clone())).unwrap())
        .await
        .unwrap();

    let verify_2fa_body = serde_json::json!({
        "email": random_email,
        "login_attempt_id": login_attempt_id,
        "2FACode": code_tuple.1.as_ref().expose_secret()
    });
    
    let response = app.post_verify_2fa(&verify_2fa_body).await;
    assert_eq!(response.status().as_u16(), 200);
    let auth_cookie = response.cookies().find(|cookie| cookie.name() == JWT_COOKIE_NAME).expect("No auth cookie found");
    assert!(!auth_cookie.value().is_empty());
    
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_same_code_twice() {    
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    });
    
    let response = app.post_signup(&signup_body).await;
    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
    });
    
    let response = app.post_login(&login_body).await;
    assert_eq!(response.status().as_u16(), 206);
    
    let json_body = response.json::<TwoFactorAuthResponse>().await.expect("Could not deserialize response body to TwoFactorAuthResponse");
    let login_attempt_id = json_body.login_attempt_id;

    let code_tuple = app
        .two_fa_code_store
        .read()
        .await
        .get_code(&Email::parse(Secret::new(random_email.clone())).unwrap())
        .await.unwrap();

    let verify_2fa_body = serde_json::json!({
        "email": random_email,
        "login_attempt_id": login_attempt_id,
        "2FACode": code_tuple.1.as_ref().expose_secret()
    });
    
    let response = app.post_verify_2fa(&verify_2fa_body).await;
    assert_eq!(response.status().as_u16(), 200);

    let response = app.post_verify_2fa(&verify_2fa_body).await;
    assert_eq!(response.status().as_u16(), 401);
    
    app.clean_up().await;
}
