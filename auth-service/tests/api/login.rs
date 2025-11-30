use crate::helpers::{get_random_email, TestApp};
use auth_service::{ErrorResponse, domain::Email, routes::TwoFactorAuthResponse, utils::JWT_COOKIE_NAME};
use secrecy::{ExposeSecret, Secret};
use wiremock::{Mock, ResponseTemplate, matchers::{method, path}};

#[tokio::test]
async fn should_return_422_if_malformed_credentials() {
    let app = TestApp::new().await;
    let malformed_credential = serde_json::json!({});

    let response = app.post_login(&malformed_credential).await;

    assert_eq!(response.status().as_u16(), 422, "Failed for input: {:?}", malformed_credential);
    
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    // Call the log-in route with invalid credentials and assert that a
    // 400 HTTP status code is returned along with the appropriate error message. 
    let app = TestApp::new().await;

    let invalid_credentials = serde_json::json!({
        "email": "",
        "password": "password123"
    });

    let response = app.post_login(&invalid_credentials).await;

    assert_eq!(response.status().as_u16(), 400, "Failed for input: {:?}", invalid_credentials);

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "Invalid credentials".to_owned()
    );
    
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_200_if_valid_credentials_and_2fa_disabled() {
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": false
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
    });

    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 200);

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());
    
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_206_if_valid_credentials_and_2fa_enabled() {
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    });
    
    let response = app.post_signup(&signup_body).await;
    assert_eq!(response.status().as_u16(), 201);

    // Define an expectation for the mock server
    Mock::given(path("/email")) // Expect an HTTP request to the "/email" path
        .and(method("POST")) // Expect the HTTP method to be POST
        .respond_with(ResponseTemplate::new(200)) // Respond with an HTTP 200 OK status
        .expect(1) // Expect this request to be made exactly once
        .mount(&app.email_server) // Mount this expectation on the mock email server
        .await; // Await the asynchronous operation to ensure the mock server is set up before proceeding

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
    });
    
    let response = app.post_login(&login_body).await;
    assert_eq!(response.status().as_u16(), 206);

    // TODO: assert that `json_body.login_attempt_id` is stored inside `app.two_fa_code_store`
    let json_body = response.json::<TwoFactorAuthResponse>().await.expect("Could not deserialize response body to TwoFactorAuthResponse");
    assert_eq!(json_body.message, "2FA required".to_owned());

    let two_fa_code_store = app.two_fa_code_store.read().await;
    let (login_attempt_id, _) = two_fa_code_store.get_code(&Email::parse(Secret::new(random_email)).unwrap()).await.unwrap();
    assert_eq!(json_body.login_attempt_id, login_attempt_id.as_ref().expose_secret().to_owned());
    
    app.clean_up().await;
}