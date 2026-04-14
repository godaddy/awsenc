use chrono::{DateTime, Utc};
use regex::Regex;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};
use url::Url;
use zeroize::Zeroizing;

use crate::mfa::MfaChallenge;
use crate::{Error, Result};

/// An Okta session payload retained only for cache-format compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OktaSession {
    pub session_id: String,
    pub expiration: DateTime<Utc>,
}

/// Okta authentication API client.
#[derive(Debug)]
pub struct OktaClient {
    client: reqwest::Client,
    base_url: String,
}

/// Response states from Okta's `/api/v1/authn` endpoint.
#[derive(Debug)]
pub enum AuthnResponse {
    /// Authentication succeeded; a session token is available.
    Success { session_token: Zeroizing<String> },
    /// MFA is required before authentication can complete.
    MfaRequired {
        state_token: Zeroizing<String>,
        factors: Vec<MfaChallenge>,
    },
    /// MFA challenge has been issued (e.g., push sent); check `factor_result`.
    MfaChallenge {
        state_token: Zeroizing<String>,
        factor_result: String,
    },
}

// ---------------------------------------------------------------------------
// Internal serde types for Okta JSON responses
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OktaAuthnRaw {
    status: Option<String>,
    session_token: Option<String>,
    state_token: Option<String>,
    factor_result: Option<String>,
    #[serde(rename = "_embedded")]
    embedded: Option<OktaEmbedded>,
}

#[derive(Debug, Deserialize)]
struct OktaEmbedded {
    factors: Option<Vec<OktaFactor>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OktaFactor {
    id: String,
    factor_type: String,
    provider: String,
    profile: Option<OktaFactorProfile>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OktaFactorProfile {
    credential_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OktaErrorResponse {
    error_summary: Option<String>,
    #[allow(dead_code)]
    error_code: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthnRequest {
    username: String,
    password: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct VerifyTotpRequest {
    state_token: String,
    pass_code: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct VerifyPushRequest {
    state_token: String,
}

impl OktaClient {
    /// Create a new Okta API client for the given organization domain.
    ///
    /// `organization` should be the full Okta domain, e.g. `mycompany.okta.com`.
    pub fn new(organization: &str) -> Result<Self> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let base_url = format!("https://{organization}");
        Ok(Self { client, base_url })
    }

    /// Create an Okta client pointing at a custom base URL (for testing).
    pub fn with_base_url(base_url: &str) -> Result<Self> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            client,
            base_url: base_url.to_owned(),
        })
    }

    /// Authenticate a user with username and password.
    ///
    /// Returns `Success` with a session token, or `MfaRequired` with available factors.
    pub async fn authenticate(
        &self,
        username: &str,
        password: &Zeroizing<String>,
    ) -> Result<AuthnResponse> {
        let url = format!("{}/api/v1/authn", self.base_url);
        let body = AuthnRequest {
            username: username.to_owned(),
            password: password.as_str().to_owned(),
        };

        let resp = self
            .client
            .post(&url)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .json(&body)
            .send()
            .await?;

        let status = resp.status();
        let text = resp.text().await?;

        if !status.is_success() {
            let err_msg = parse_okta_error(&text);
            return Err(Error::Auth(format!(
                "Okta authentication failed (HTTP {status}): {err_msg}"
            )));
        }

        parse_authn_response(&text)
    }

    /// Verify a TOTP code for the given factor.
    pub async fn verify_totp(
        &self,
        factor_id: &str,
        state_token: &Zeroizing<String>,
        passcode: &str,
    ) -> Result<AuthnResponse> {
        let url = format!(
            "{}/api/v1/authn/factors/{}/verify",
            self.base_url, factor_id
        );
        let body = VerifyTotpRequest {
            state_token: state_token.as_str().to_owned(),
            pass_code: passcode.to_owned(),
        };

        let resp = self
            .client
            .post(&url)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .json(&body)
            .send()
            .await?;

        let status = resp.status();
        let text = resp.text().await?;

        if !status.is_success() {
            let err_msg = parse_okta_error(&text);
            return Err(Error::Mfa(format!(
                "TOTP verification failed (HTTP {status}): {err_msg}"
            )));
        }

        parse_authn_response(&text)
    }

    /// Initiate a push notification for the given factor.
    ///
    /// Returns an `MfaChallenge` with `factor_result` set to `WAITING`.
    pub async fn verify_push(
        &self,
        factor_id: &str,
        state_token: &Zeroizing<String>,
    ) -> Result<AuthnResponse> {
        let url = format!(
            "{}/api/v1/authn/factors/{}/verify",
            self.base_url, factor_id
        );
        let body = VerifyPushRequest {
            state_token: state_token.as_str().to_owned(),
        };

        let resp = self
            .client
            .post(&url)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .json(&body)
            .send()
            .await?;

        let status = resp.status();
        let text = resp.text().await?;

        if !status.is_success() {
            let err_msg = parse_okta_error(&text);
            return Err(Error::Mfa(format!(
                "push verification failed (HTTP {status}): {err_msg}"
            )));
        }

        parse_authn_response(&text)
    }

    /// Poll for push approval at 2-second intervals until success, rejection, or timeout.
    pub async fn poll_push(
        &self,
        factor_id: &str,
        state_token: &Zeroizing<String>,
        timeout: std::time::Duration,
    ) -> Result<AuthnResponse> {
        let start = std::time::Instant::now();

        loop {
            let result = self.verify_push(factor_id, state_token).await?;

            match &result {
                AuthnResponse::Success { .. } => return Ok(result),
                AuthnResponse::MfaChallenge { factor_result, .. } => match factor_result.as_str() {
                    "WAITING" => {
                        if start.elapsed() >= timeout {
                            return Err(Error::Timeout("push notification timed out".into()));
                        }
                        debug!("push verification waiting, polling again in 2s");
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    }
                    "REJECTED" => {
                        return Err(Error::Mfa("push notification was rejected".into()));
                    }
                    "TIMEOUT" => {
                        return Err(Error::Timeout(
                            "push notification timed out on server".into(),
                        ));
                    }
                    other => {
                        return Err(Error::Mfa(format!(
                            "unexpected push factor result: {other}"
                        )));
                    }
                },
                AuthnResponse::MfaRequired { .. } => {
                    return Err(Error::Mfa(
                        "unexpected MFA_REQUIRED during push polling".into(),
                    ));
                }
            }
        }
    }

    /// Verify a `YubiKey` OTP.
    pub async fn verify_yubikey(
        &self,
        factor_id: &str,
        state_token: &Zeroizing<String>,
        otp: &str,
    ) -> Result<AuthnResponse> {
        // YubiKey OTP uses the same verify endpoint with passCode
        self.verify_totp(factor_id, state_token, otp).await
    }

    /// Get a SAML assertion by presenting a session token to an Okta app URL.
    ///
    /// The `app_url` is the Okta SAML app embed link, e.g.:
    /// `https://mycompany.okta.com/home/amazon_aws/0oa.../272`
    pub async fn get_saml_assertion(
        &self,
        session_token: &Zeroizing<String>,
        app_url: &str,
    ) -> Result<String> {
        let mut url = Url::parse(app_url)?;
        url.query_pairs_mut()
            .append_pair("sessionToken", session_token.as_str());
        self.fetch_saml_assertion(url, None).await
    }

    /// Get a SAML assertion for a validated Okta application URL on the trusted Okta host.
    pub async fn get_saml_assertion_for_org(
        &self,
        session_token: &Zeroizing<String>,
        app_url: &str,
        trusted_host: &str,
    ) -> Result<String> {
        let mut url = Url::parse(app_url)?;
        if url.scheme() != "https" {
            return Err(Error::Saml(format!(
                "Okta application URL must use https: {app_url}"
            )));
        }
        let Some(host) = url.host_str() else {
            return Err(Error::Saml(format!(
                "Okta application URL must include a host: {app_url}"
            )));
        };
        if host != trusted_host {
            return Err(Error::Saml(format!(
                "Okta application host must match trusted Okta organization ({trusted_host}): {app_url}"
            )));
        }
        if url
            .query_pairs()
            .any(|(key, _)| key.eq_ignore_ascii_case("sessionToken"))
        {
            return Err(Error::Saml(format!(
                "Okta application URL must not include a sessionToken query parameter: {app_url}"
            )));
        }
        url.query_pairs_mut()
            .append_pair("sessionToken", session_token.as_str());
        self.fetch_saml_assertion(url, Some(trusted_host)).await
    }

    async fn fetch_saml_assertion(&self, url: Url, trusted_host: Option<&str>) -> Result<String> {
        let resp = self
            .client
            .get(url.clone())
            .header(ACCEPT, "text/html")
            .send()
            .await?;

        // Follow the redirect chain manually if needed
        let status = resp.status();
        if status.is_redirection() {
            if let Some(location) = resp.headers().get("location") {
                let redirect_location = location
                    .to_str()
                    .map_err(|_| Error::Saml("invalid redirect location header".into()))?;
                let redirect_url = url.join(redirect_location)?;
                if let Some(host) = trusted_host {
                    ensure_trusted_redirect(&redirect_url, host)?;
                }
                debug!("following SAML redirect to {redirect_url}");
                let resp2 = self.client.get(redirect_url).send().await?;
                let html = resp2.text().await?;
                return extract_saml_assertion(&html);
            }
        }

        if !status.is_success() {
            return Err(Error::Saml(format!(
                "failed to get SAML assertion (HTTP {status})"
            )));
        }

        let html = resp.text().await?;
        extract_saml_assertion(&html)
    }

    /// Get a SAML assertion using an existing Okta session cookie.
    ///
    /// This path is intentionally disabled until a supported Okta session model
    /// is implemented.
    pub async fn get_saml_with_session(&self, session_id: &str, app_url: &str) -> Result<String> {
        let _ = (session_id, app_url);
        warn!("transparent Okta session reuse is disabled");
        Err(Error::Auth(
            "transparent Okta session reuse is disabled; run 'awsenc auth'".into(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn parse_authn_response(text: &str) -> Result<AuthnResponse> {
    let raw: OktaAuthnRaw =
        serde_json::from_str(text).map_err(|e| Error::Auth(format!("bad Okta response: {e}")))?;

    let status = raw.status.as_deref().unwrap_or("UNKNOWN");

    match status {
        "SUCCESS" => {
            let token = raw
                .session_token
                .ok_or_else(|| Error::Auth("SUCCESS response missing session_token".into()))?;
            Ok(AuthnResponse::Success {
                session_token: Zeroizing::new(token),
            })
        }
        "MFA_REQUIRED" => {
            let state_token = raw
                .state_token
                .ok_or_else(|| Error::Auth("MFA_REQUIRED response missing state_token".into()))?;

            let factors = raw
                .embedded
                .and_then(|e| e.factors)
                .unwrap_or_default()
                .into_iter()
                .map(|f| MfaChallenge {
                    factor_id: f.id,
                    factor_type: f.factor_type,
                    provider: f.provider,
                    profile: f.profile.and_then(|p| p.credential_id),
                })
                .collect();

            Ok(AuthnResponse::MfaRequired {
                state_token: Zeroizing::new(state_token),
                factors,
            })
        }
        "MFA_CHALLENGE" => {
            let state_token = raw
                .state_token
                .ok_or_else(|| Error::Auth("MFA_CHALLENGE response missing state_token".into()))?;
            let factor_result = raw.factor_result.unwrap_or_else(|| "WAITING".to_owned());
            Ok(AuthnResponse::MfaChallenge {
                state_token: Zeroizing::new(state_token),
                factor_result,
            })
        }
        other => Err(Error::Auth(format!("unexpected Okta status: {other}"))),
    }
}

fn ensure_trusted_redirect(url: &Url, trusted_host: &str) -> Result<()> {
    let Some(host) = url.host_str() else {
        return Err(Error::Saml(format!("redirect target missing host: {url}")));
    };
    if host == trusted_host || host == "signin.aws.amazon.com" {
        return Ok(());
    }
    Err(Error::Saml(format!(
        "refusing redirect to untrusted host: {host}"
    )))
}

fn parse_okta_error(text: &str) -> String {
    serde_json::from_str::<OktaErrorResponse>(text)
        .ok()
        .and_then(|e| e.error_summary)
        .unwrap_or_else(|| text.chars().take(200).collect())
}

/// Extract the base64 SAML assertion from the Okta HTML response.
///
/// Okta returns an HTML form with a hidden input: `<input name="SAMLResponse" value="...">`
fn extract_saml_assertion(html: &str) -> Result<String> {
    let re = Regex::new(r#"name="SAMLResponse"\s+value="([^"]+)""#)?;

    // Also handle value before name ordering
    let re_alt = Regex::new(r#"value="([^"]+)"\s+name="SAMLResponse""#)?;

    if let Some(caps) = re.captures(html) {
        return Ok(caps[1].to_owned());
    }

    if let Some(caps) = re_alt.captures(html) {
        return Ok(caps[1].to_owned());
    }

    Err(Error::Saml(
        "could not find SAMLResponse in Okta HTML response".into(),
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn parse_success_response() {
        let json = r#"{
            "status": "SUCCESS",
            "sessionToken": "abc123token"
        }"#;
        let result = parse_authn_response(json).unwrap();
        match result {
            AuthnResponse::Success { session_token } => {
                assert_eq!(session_token.as_str(), "abc123token");
            }
            _ => panic!("expected Success"),
        }
    }

    #[test]
    fn parse_mfa_required_response() {
        let json = r#"{
            "status": "MFA_REQUIRED",
            "stateToken": "state123",
            "_embedded": {
                "factors": [
                    {
                        "id": "factor1",
                        "factorType": "push",
                        "provider": "OKTA",
                        "profile": {
                            "credentialId": "user@example.com"
                        }
                    },
                    {
                        "id": "factor2",
                        "factorType": "token:hardware",
                        "provider": "YUBICO"
                    }
                ]
            }
        }"#;
        let result = parse_authn_response(json).unwrap();
        match result {
            AuthnResponse::MfaRequired {
                state_token,
                factors,
            } => {
                assert_eq!(state_token.as_str(), "state123");
                assert_eq!(factors.len(), 2);
                assert_eq!(factors[0].factor_type, "push");
                assert_eq!(factors[0].provider, "OKTA");
                assert_eq!(factors[1].factor_type, "token:hardware");
                assert_eq!(factors[1].provider, "YUBICO");
            }
            _ => panic!("expected MfaRequired"),
        }
    }

    #[test]
    fn trusted_redirect_allows_okta_and_aws_hosts() {
        assert!(ensure_trusted_redirect(
            &Url::parse("https://example.okta.com/app").unwrap(),
            "example.okta.com",
        )
        .is_ok());
        assert!(ensure_trusted_redirect(
            &Url::parse("https://signin.aws.amazon.com/saml").unwrap(),
            "example.okta.com",
        )
        .is_ok());
    }

    #[test]
    fn trusted_redirect_rejects_untrusted_host() {
        let err = ensure_trusted_redirect(
            &Url::parse("https://evil.example/saml").unwrap(),
            "example.okta.com",
        )
        .unwrap_err();
        assert!(err.to_string().contains("refusing redirect"));
    }

    #[test]
    fn parse_mfa_challenge_response() {
        let json = r#"{
            "status": "MFA_CHALLENGE",
            "stateToken": "stateABC",
            "factorResult": "WAITING"
        }"#;
        let result = parse_authn_response(json).unwrap();
        match result {
            AuthnResponse::MfaChallenge {
                state_token,
                factor_result,
            } => {
                assert_eq!(state_token.as_str(), "stateABC");
                assert_eq!(factor_result, "WAITING");
            }
            _ => panic!("expected MfaChallenge"),
        }
    }

    #[test]
    fn parse_okta_error_message() {
        let json = r#"{"errorCode":"E0000004","errorSummary":"Authentication failed"}"#;
        let msg = parse_okta_error(json);
        assert_eq!(msg, "Authentication failed");
    }

    #[test]
    fn parse_okta_error_bad_json() {
        let msg = parse_okta_error("not json at all");
        assert_eq!(msg, "not json at all");
    }

    #[test]
    fn extract_saml_from_html() {
        let html = r#"<html><body>
            <form method="post">
                <input type="hidden" name="SAMLResponse" value="PHNhbWw+dGVzdDwvc2FtbD4="/>
                <input type="hidden" name="RelayState" value=""/>
            </form>
        </body></html>"#;
        let assertion = extract_saml_assertion(html).unwrap();
        assert_eq!(assertion, "PHNhbWw+dGVzdDwvc2FtbD4=");
    }

    #[test]
    fn extract_saml_value_before_name() {
        let html = r#"<input type="hidden" value="base64data" name="SAMLResponse"/>"#;
        let assertion = extract_saml_assertion(html).unwrap();
        assert_eq!(assertion, "base64data");
    }

    #[test]
    fn extract_saml_missing() {
        let html = "<html><body>No SAML here</body></html>";
        assert!(extract_saml_assertion(html).is_err());
    }

    #[test]
    fn okta_client_new() {
        let client = OktaClient::new("mycompany.okta.com").unwrap();
        assert_eq!(client.base_url, "https://mycompany.okta.com");
    }

    #[test]
    fn parse_unknown_status() {
        let json = r#"{"status": "LOCKED_OUT"}"#;
        let result = parse_authn_response(json);
        assert!(result.is_err());
    }

    #[test]
    fn parse_mfa_challenge_rejected() {
        let json = r#"{
            "status": "MFA_CHALLENGE",
            "stateToken": "stateXYZ",
            "factorResult": "REJECTED"
        }"#;
        let result = parse_authn_response(json).unwrap();
        match result {
            AuthnResponse::MfaChallenge { factor_result, .. } => {
                assert_eq!(factor_result, "REJECTED");
            }
            _ => panic!("expected MfaChallenge"),
        }
    }
}
