#![allow(clippy::unwrap_used, clippy::panic)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use wiremock::matchers::{body_string_contains, header, method, path, path_regex, query_param};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};
use zeroize::Zeroizing;

use awsenc_core::okta::{AuthnResponse, OktaClient};
use awsenc_core::sts::StsClient;

/// A responder that cycles through a list of templates based on call count.
struct SequentialResponder {
    templates: Vec<ResponseTemplate>,
    call_count: AtomicUsize,
}

impl SequentialResponder {
    fn new(templates: Vec<ResponseTemplate>) -> Self {
        Self {
            templates,
            call_count: AtomicUsize::new(0),
        }
    }
}

impl Respond for SequentialResponder {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        let idx = self.call_count.fetch_add(1, Ordering::SeqCst);
        let clamped = idx.min(self.templates.len() - 1);
        self.templates[clamped].clone()
    }
}

// ===========================================================================
// Okta API tests
// ===========================================================================

#[tokio::test]
async fn okta_authenticate_success() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v1/authn"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "SUCCESS",
            "sessionToken": "test-session-token-abc123"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = OktaClient::with_base_url(&server.uri()).unwrap();
    let password = Zeroizing::new("correctpassword".to_string());
    let result = client.authenticate("user@example.com", &password).await;

    match result.unwrap() {
        AuthnResponse::Success { session_token } => {
            assert_eq!(session_token.as_str(), "test-session-token-abc123");
        }
        other => panic!("expected Success, got {other:?}"),
    }
}

#[tokio::test]
async fn okta_authenticate_mfa_required() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v1/authn"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "MFA_REQUIRED",
            "stateToken": "state-token-mfa-001",
            "_embedded": {
                "factors": [
                    {
                        "id": "push-factor-id",
                        "factorType": "push",
                        "provider": "OKTA",
                        "profile": {
                            "credentialId": "user@example.com"
                        }
                    },
                    {
                        "id": "totp-factor-id",
                        "factorType": "token:software:totp",
                        "provider": "OKTA",
                        "profile": {
                            "credentialId": "user@example.com"
                        }
                    },
                    {
                        "id": "yubi-factor-id",
                        "factorType": "token:hardware",
                        "provider": "YUBICO"
                    }
                ]
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = OktaClient::with_base_url(&server.uri()).unwrap();
    let password = Zeroizing::new("password".to_string());
    let result = client.authenticate("user@example.com", &password).await;

    match result.unwrap() {
        AuthnResponse::MfaRequired {
            state_token,
            factors,
        } => {
            assert_eq!(state_token.as_str(), "state-token-mfa-001");
            assert_eq!(factors.len(), 3);
            assert_eq!(factors[0].factor_id, "push-factor-id");
            assert_eq!(factors[0].factor_type, "push");
            assert_eq!(factors[0].provider, "OKTA");
            assert_eq!(factors[0].profile.as_deref(), Some("user@example.com"));
            assert_eq!(factors[1].factor_id, "totp-factor-id");
            assert_eq!(factors[1].factor_type, "token:software:totp");
            assert_eq!(factors[2].factor_id, "yubi-factor-id");
            assert_eq!(factors[2].factor_type, "token:hardware");
            assert_eq!(factors[2].provider, "YUBICO");
            assert!(factors[2].profile.is_none());
        }
        other => panic!("expected MfaRequired, got {other:?}"),
    }
}

#[tokio::test]
async fn okta_verify_totp_success() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v1/authn/factors/totp-factor-123/verify"))
        .and(body_string_contains("passCode"))
        .and(body_string_contains("stateToken"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "SUCCESS",
            "sessionToken": "session-after-totp"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = OktaClient::with_base_url(&server.uri()).unwrap();
    let state_token = Zeroizing::new("state-abc".to_string());
    let result = client
        .verify_totp("totp-factor-123", &state_token, "123456")
        .await;

    match result.unwrap() {
        AuthnResponse::Success { session_token } => {
            assert_eq!(session_token.as_str(), "session-after-totp");
        }
        other => panic!("expected Success, got {other:?}"),
    }
}

#[tokio::test]
async fn okta_verify_yubikey_success() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v1/authn/factors/yubi-factor-456/verify"))
        .and(body_string_contains("passCode"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "SUCCESS",
            "sessionToken": "session-after-yubikey"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = OktaClient::with_base_url(&server.uri()).unwrap();
    let state_token = Zeroizing::new("state-yubikey".to_string());
    let result = client
        .verify_yubikey("yubi-factor-456", &state_token, "cccjgjgkhcbbcccccccc")
        .await;

    match result.unwrap() {
        AuthnResponse::Success { session_token } => {
            assert_eq!(session_token.as_str(), "session-after-yubikey");
        }
        other => panic!("expected Success, got {other:?}"),
    }
}

#[tokio::test]
async fn okta_push_verification_waiting_then_success() {
    let server = MockServer::start().await;

    // First call returns WAITING, second returns SUCCESS.
    let responder = SequentialResponder::new(vec![
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "MFA_CHALLENGE",
            "stateToken": "state-push",
            "factorResult": "WAITING"
        })),
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "SUCCESS",
            "sessionToken": "session-after-push"
        })),
    ]);

    Mock::given(method("POST"))
        .and(path("/api/v1/authn/factors/push-factor-789/verify"))
        .respond_with(responder)
        .expect(2)
        .mount(&server)
        .await;

    let client = OktaClient::with_base_url(&server.uri()).unwrap();
    let state_token = Zeroizing::new("state-push".to_string());
    let result = client
        .poll_push("push-factor-789", &state_token, Duration::from_secs(30))
        .await;

    match result.unwrap() {
        AuthnResponse::Success { session_token } => {
            assert_eq!(session_token.as_str(), "session-after-push");
        }
        other => panic!("expected Success, got {other:?}"),
    }
}

#[tokio::test]
async fn okta_push_verification_rejected() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v1/authn/factors/push-factor-rej/verify"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "MFA_CHALLENGE",
            "stateToken": "state-rej",
            "factorResult": "REJECTED"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = OktaClient::with_base_url(&server.uri()).unwrap();
    let state_token = Zeroizing::new("state-rej".to_string());
    let result = client
        .poll_push("push-factor-rej", &state_token, Duration::from_secs(30))
        .await;

    let err = result.unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("rejected"),
        "expected 'rejected' in error: {msg}"
    );
}

#[tokio::test]
async fn okta_push_verification_timeout() {
    let server = MockServer::start().await;

    // Always return WAITING -- poll_push should time out.
    Mock::given(method("POST"))
        .and(path("/api/v1/authn/factors/push-factor-timeout/verify"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "MFA_CHALLENGE",
            "stateToken": "state-timeout",
            "factorResult": "WAITING"
        })))
        .mount(&server)
        .await;

    let client = OktaClient::with_base_url(&server.uri()).unwrap();
    let state_token = Zeroizing::new("state-timeout".to_string());

    // Use a very short timeout so the test doesn't take long.
    let result = client
        .poll_push(
            "push-factor-timeout",
            &state_token,
            Duration::from_millis(100),
        )
        .await;

    let err = result.unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("timed out"),
        "expected 'timed out' in error: {msg}"
    );
}

#[tokio::test]
async fn okta_authentication_failure_401() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v1/authn"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "errorCode": "E0000004",
            "errorSummary": "Authentication failed",
            "errorLink": "E0000004",
            "errorId": "oaeFUbNRFT6XCRDQ",
            "errorCauses": []
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = OktaClient::with_base_url(&server.uri()).unwrap();
    let password = Zeroizing::new("wrongpassword".to_string());
    let result = client.authenticate("user@example.com", &password).await;

    let err = result.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("401"), "expected '401' in error: {msg}");
    assert!(
        msg.contains("Authentication failed"),
        "expected 'Authentication failed' in error: {msg}"
    );
}

#[tokio::test]
async fn okta_saml_assertion_extraction() {
    let server = MockServer::start().await;

    let saml_html = r#"<html>
<body>
<form method="post" action="https://signin.aws.amazon.com/saml">
    <input type="hidden" name="SAMLResponse" value="PHNhbWw+dGVzdGRhdGE8L3NhbWw+"/>
    <input type="hidden" name="RelayState" value=""/>
    <input type="submit" value="Submit"/>
</form>
</body>
</html>"#;

    Mock::given(method("GET"))
        .and(path("/home/amazon_aws/0oa123abc/272"))
        .and(query_param("sessionToken", "session-for-saml"))
        .respond_with(ResponseTemplate::new(200).set_body_string(saml_html))
        .expect(1)
        .mount(&server)
        .await;

    let client = OktaClient::with_base_url(&server.uri()).unwrap();
    let session_token = Zeroizing::new("session-for-saml".to_string());
    let app_url = format!("{}/home/amazon_aws/0oa123abc/272", server.uri());
    let result = client
        .get_saml_assertion(&session_token, &app_url)
        .await
        .unwrap();

    assert_eq!(result, "PHNhbWw+dGVzdGRhdGE8L3NhbWw+");
}

#[tokio::test]
async fn okta_saml_assertion_missing() {
    let server = MockServer::start().await;

    let no_saml_html = r"<html>
<body>
<p>Welcome to Okta. No SAML for you.</p>
</body>
</html>";

    Mock::given(method("GET"))
        .and(path("/home/amazon_aws/0oa_missing/272"))
        .respond_with(ResponseTemplate::new(200).set_body_string(no_saml_html))
        .expect(1)
        .mount(&server)
        .await;

    let client = OktaClient::with_base_url(&server.uri()).unwrap();
    let session_token = Zeroizing::new("token".to_string());
    let app_url = format!("{}/home/amazon_aws/0oa_missing/272", server.uri());
    let result = client.get_saml_assertion(&session_token, &app_url).await;

    let err = result.unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("SAMLResponse"),
        "expected 'SAMLResponse' in error: {msg}"
    );
}

#[tokio::test]
async fn okta_session_based_saml() {
    let server = MockServer::start().await;

    let saml_html = r#"<html>
<body>
<form method="post">
    <input type="hidden" name="SAMLResponse" value="c2Vzc2lvbi1iYXNlZC1zYW1s"/>
</form>
</body>
</html>"#;

    Mock::given(method("GET"))
        .and(path("/home/amazon_aws/0oa_session/272"))
        .and(header("cookie", "sid=cached-session-id-xyz"))
        .respond_with(ResponseTemplate::new(200).set_body_string(saml_html))
        .expect(1)
        .mount(&server)
        .await;

    let client = OktaClient::with_base_url(&server.uri()).unwrap();
    let app_url = format!("{}/home/amazon_aws/0oa_session/272", server.uri());
    let result = client
        .get_saml_with_session("cached-session-id-xyz", &app_url)
        .await
        .unwrap();

    assert_eq!(result, "c2Vzc2lvbi1iYXNlZC1zYW1s");
}

#[tokio::test]
async fn okta_create_session_returns_cookie_id() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v1/sessions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "sid-real-session-id",
            "expiresAt": "2026-04-11T20:00:00Z"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = OktaClient::with_base_url(&server.uri()).unwrap();
    let session_token = Zeroizing::new("one-time-session-token".to_string());
    let session = client.create_session(&session_token).await.unwrap();

    assert_eq!(session.session_id, "sid-real-session-id");
    assert_eq!(session.expiration.to_rfc3339(), "2026-04-11T20:00:00+00:00");
}

#[tokio::test]
async fn okta_session_expired_redirect() {
    let server = MockServer::start().await;

    // When the session is expired, Okta returns a redirect.
    Mock::given(method("GET"))
        .and(path("/home/amazon_aws/0oa_expired/272"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("location", "https://login.okta.com"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = OktaClient::with_base_url(&server.uri()).unwrap();
    let app_url = format!("{}/home/amazon_aws/0oa_expired/272", server.uri());
    let result = client
        .get_saml_with_session("expired-session-id", &app_url)
        .await;

    let err = result.unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("expired") || msg.contains("redirect"),
        "expected session-expired error: {msg}"
    );
}

// ===========================================================================
// STS API tests
// ===========================================================================

#[tokio::test]
async fn sts_assume_role_with_saml_success() {
    let server = MockServer::start().await;

    let sts_xml = r#"<AssumeRoleWithSAMLResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithSAMLResult>
    <Credentials>
      <AccessKeyId>ASIATESTKEYID123</AccessKeyId>
      <SecretAccessKey>testsecretaccesskey456</SecretAccessKey>
      <SessionToken>FwoGZXIvYXdzEBYaDH-test-session-token</SessionToken>
      <Expiration>2026-04-11T20:00:00Z</Expiration>
    </Credentials>
    <AssumedRoleUser>
      <AssumedRoleId>AROATESTIDROLE:user@example.com</AssumedRoleId>
      <Arn>arn:aws:sts::123456789012:assumed-role/TestRole/user@example.com</Arn>
    </AssumedRoleUser>
  </AssumeRoleWithSAMLResult>
</AssumeRoleWithSAMLResponse>"#;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_string_contains("Action=AssumeRoleWithSAML"))
        .respond_with(ResponseTemplate::new(200).set_body_string(sts_xml))
        .expect(1)
        .mount(&server)
        .await;

    let client = StsClient::with_endpoint(&server.uri());
    let creds = client
        .assume_role_with_saml(
            "arn:aws:iam::123456789012:role/TestRole",
            "arn:aws:iam::123456789012:saml-provider/Okta",
            "base64-saml-assertion",
            3600,
        )
        .await
        .unwrap();

    assert_eq!(creds.access_key_id, "ASIATESTKEYID123");
    assert_eq!(creds.secret_access_key.as_str(), "testsecretaccesskey456");
    assert_eq!(
        creds.session_token.as_str(),
        "FwoGZXIvYXdzEBYaDH-test-session-token"
    );
    assert_eq!(creds.expiration.to_rfc3339(), "2026-04-11T20:00:00+00:00");
}

#[tokio::test]
async fn sts_assume_role_expired_saml() {
    let server = MockServer::start().await;

    let error_xml = r#"<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error>
    <Type>Sender</Type>
    <Code>ExpiredTokenException</Code>
    <Message>Token must be redeemed within 5 minutes of issuance</Message>
  </Error>
  <RequestId>abc-123-def</RequestId>
</ErrorResponse>"#;

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(400).set_body_string(error_xml))
        .expect(1)
        .mount(&server)
        .await;

    let client = StsClient::with_endpoint(&server.uri());
    let result = client
        .assume_role_with_saml(
            "arn:aws:iam::123:role/R",
            "arn:aws:iam::123:saml-provider/O",
            "expired-saml",
            3600,
        )
        .await;

    let err = result.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("400"), "expected HTTP 400 in error: {msg}");
    assert!(
        msg.contains("redeemed within 5 minutes"),
        "expected expiration message in error: {msg}"
    );
}

#[tokio::test]
async fn sts_assume_role_invalid_role_403() {
    let server = MockServer::start().await;

    let error_xml = r#"<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error>
    <Type>Sender</Type>
    <Code>AccessDenied</Code>
    <Message>Not authorized to perform sts:AssumeRoleWithSAML</Message>
  </Error>
  <RequestId>xyz-456</RequestId>
</ErrorResponse>"#;

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(403).set_body_string(error_xml))
        .expect(1)
        .mount(&server)
        .await;

    let client = StsClient::with_endpoint(&server.uri());
    let result = client
        .assume_role_with_saml(
            "arn:aws:iam::999:role/Nonexistent",
            "arn:aws:iam::999:saml-provider/O",
            "saml-data",
            3600,
        )
        .await;

    let err = result.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("403"), "expected HTTP 403 in error: {msg}");
    assert!(
        msg.contains("Not authorized"),
        "expected access denied message in error: {msg}"
    );
}

#[tokio::test]
async fn sts_malformed_xml_response() {
    let server = MockServer::start().await;

    // Returns 200 but with XML missing required fields.
    let bad_xml = r"<AssumeRoleWithSAMLResponse>
  <AssumeRoleWithSAMLResult>
    <Credentials>
      <AccessKeyId>AKID_ONLY</AccessKeyId>
    </Credentials>
  </AssumeRoleWithSAMLResult>
</AssumeRoleWithSAMLResponse>";

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(bad_xml))
        .expect(1)
        .mount(&server)
        .await;

    let client = StsClient::with_endpoint(&server.uri());
    let result = client
        .assume_role_with_saml(
            "arn:aws:iam::123:role/R",
            "arn:aws:iam::123:saml-provider/O",
            "saml",
            3600,
        )
        .await;

    let err = result.unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("missing SecretAccessKey"),
        "expected missing field error: {msg}"
    );
}

#[tokio::test]
async fn sts_completely_invalid_xml() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string("this is not xml at all"))
        .expect(1)
        .mount(&server)
        .await;

    let client = StsClient::with_endpoint(&server.uri());
    let result = client
        .assume_role_with_saml(
            "arn:aws:iam::123:role/R",
            "arn:aws:iam::123:saml-provider/O",
            "saml",
            3600,
        )
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn sts_empty_body_error() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(500).set_body_string(""))
        .expect(1)
        .mount(&server)
        .await;

    let client = StsClient::with_endpoint(&server.uri());
    let result = client
        .assume_role_with_saml(
            "arn:aws:iam::123:role/R",
            "arn:aws:iam::123:saml-provider/O",
            "saml",
            3600,
        )
        .await;

    let err = result.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("500"), "expected HTTP 500 in error: {msg}");
}

// ===========================================================================
// Okta -- additional edge cases
// ===========================================================================

#[tokio::test]
async fn okta_verify_totp_wrong_code_403() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex("/api/v1/authn/factors/.*/verify"))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "errorCode": "E0000068",
            "errorSummary": "Invalid Passcode/Answer"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = OktaClient::with_base_url(&server.uri()).unwrap();
    let state_token = Zeroizing::new("state".to_string());
    let result = client
        .verify_totp("factor-id", &state_token, "000000")
        .await;

    let err = result.unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("Invalid Passcode"),
        "expected passcode error: {msg}"
    );
}

#[tokio::test]
async fn okta_authenticate_server_error_500() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v1/authn"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .expect(1)
        .mount(&server)
        .await;

    let client = OktaClient::with_base_url(&server.uri()).unwrap();
    let password = Zeroizing::new("pass".to_string());
    let result = client.authenticate("user@example.com", &password).await;

    let err = result.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("500"), "expected 500 in error: {msg}");
}

#[tokio::test]
async fn okta_saml_non_200_response() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/home/amazon_aws/0oa_fail/272"))
        .respond_with(ResponseTemplate::new(403).set_body_string("Forbidden"))
        .expect(1)
        .mount(&server)
        .await;

    let client = OktaClient::with_base_url(&server.uri()).unwrap();
    let session_token = Zeroizing::new("tok".to_string());
    let app_url = format!("{}/home/amazon_aws/0oa_fail/272", server.uri());
    let result = client.get_saml_assertion(&session_token, &app_url).await;

    let err = result.unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("403") || msg.contains("SAML"),
        "expected failure info: {msg}"
    );
}

#[tokio::test]
async fn okta_mfa_required_empty_factors() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v1/authn"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "MFA_REQUIRED",
            "stateToken": "state-empty-factors",
            "_embedded": {
                "factors": []
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = OktaClient::with_base_url(&server.uri()).unwrap();
    let password = Zeroizing::new("pass".to_string());
    let result = client.authenticate("user@example.com", &password).await;

    match result.unwrap() {
        AuthnResponse::MfaRequired { factors, .. } => {
            assert!(factors.is_empty());
        }
        other => panic!("expected MfaRequired, got {other:?}"),
    }
}

#[tokio::test]
async fn okta_verify_push_initial_waiting() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v1/authn/factors/push-id/verify"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "MFA_CHALLENGE",
            "stateToken": "state-push-wait",
            "factorResult": "WAITING"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = OktaClient::with_base_url(&server.uri()).unwrap();
    let state_token = Zeroizing::new("state-push-wait".to_string());
    let result = client.verify_push("push-id", &state_token).await;

    match result.unwrap() {
        AuthnResponse::MfaChallenge {
            factor_result,
            state_token,
        } => {
            assert_eq!(factor_result, "WAITING");
            assert_eq!(state_token.as_str(), "state-push-wait");
        }
        other => panic!("expected MfaChallenge, got {other:?}"),
    }
}

// ===========================================================================
// STS -- request validation
// ===========================================================================

#[tokio::test]
async fn sts_sends_correct_form_params() {
    let server = MockServer::start().await;

    let sts_xml = r"<AssumeRoleWithSAMLResponse>
  <AssumeRoleWithSAMLResult>
    <Credentials>
      <AccessKeyId>AKID</AccessKeyId>
      <SecretAccessKey>SECRET</SecretAccessKey>
      <SessionToken>TOKEN</SessionToken>
      <Expiration>2026-04-11T23:59:59Z</Expiration>
    </Credentials>
  </AssumeRoleWithSAMLResult>
</AssumeRoleWithSAMLResponse>";

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_string_contains("Action=AssumeRoleWithSAML"))
        .and(body_string_contains("Version=2011-06-15"))
        .and(body_string_contains("RoleArn=arn"))
        .and(body_string_contains("PrincipalArn=arn"))
        .and(body_string_contains("SAMLAssertion="))
        .respond_with(ResponseTemplate::new(200).set_body_string(sts_xml))
        .expect(1)
        .mount(&server)
        .await;

    let client = StsClient::with_endpoint(&server.uri());
    let result = client
        .assume_role_with_saml(
            "arn:aws:iam::123:role/R",
            "arn:aws:iam::123:saml-provider/O",
            "bXkgc2FtbA==",
            3600,
        )
        .await;

    assert!(result.is_ok());
}
