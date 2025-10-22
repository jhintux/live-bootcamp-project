use crate::helpers::TestApp;
use auth_service::ErrorResponse;

#[tokio::test]
async fn should_return_422_if_malformed_credentials() {
    let app = TestApp::new().await;
    let malformed_credential = serde_json::json!({});

    let response = app.post_login(&malformed_credential).await;

    assert_eq!(response.status().as_u16(), 422, "Failed for input: {:?}", malformed_credential);
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
}