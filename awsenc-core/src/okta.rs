use chrono::{DateTime, Utc};
use reqwest::header::{ACCEPT, CONTENT_TYPE, COOKIE};
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, warn};
use url::Url;
use zeroize::Zeroizing;

use crate::mfa::MfaChallenge;
use crate::{Error, Result};

/// An authenticated Okta session that can be cached.
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

const OKTA_HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_SAML_REDIRECTS: usize = 10;
const MAX_OKTA_RESPONSE_BYTES: usize = 256 * 1024;

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
struct AuthnRequest<'req> {
    username: &'req str,
    password: &'req str,
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateSessionRequest {
    session_token: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateSessionResponse {
    id: String,
    expires_at: DateTime<Utc>,
}

#[derive(Debug)]
struct HtmlFetchResult {
    final_url: Url,
    html: String,
    redirects_followed: usize,
}

impl OktaClient {
    /// Create a new Okta API client for the given organization domain.
    ///
    /// `organization` should be the full Okta domain, e.g. `mycompany.okta.com`.
    pub fn new(organization: &str) -> Result<Self> {
        let organization = validate_okta_organization(organization)?;
        let base_url = format!("https://{organization}");
        Self::with_base_url_and_timeout(&base_url, OKTA_HTTP_TIMEOUT)
    }

    /// Create an Okta client pointing at a custom base URL (for testing).
    pub fn with_base_url(base_url: &str) -> Result<Self> {
        Self::with_base_url_and_timeout(base_url, OKTA_HTTP_TIMEOUT)
    }

    fn with_base_url_and_timeout(base_url: &str, timeout: Duration) -> Result<Self> {
        let client = build_okta_http_client(timeout)?;
        Ok(Self {
            client,
            base_url: base_url.to_owned(),
        })
    }

    fn validated_app_url(&self, app_url: &str) -> Result<Url> {
        validate_okta_app_url_against_base_url(&self.base_url, app_url)
    }

    fn saml_url_with_session_token(&self, app_url: &str, session_token: &str) -> Result<Url> {
        let mut url = self.validated_app_url(app_url)?;
        url.query_pairs_mut()
            .append_pair("sessionToken", session_token);
        Ok(url)
    }

    fn base_origin(&self) -> Result<url::Origin> {
        Ok(Url::parse(&self.base_url)?.origin())
    }

    async fn fetch_html_following_redirects(
        &self,
        mut url: Url,
        session_id: Option<&str>,
    ) -> Result<HtmlFetchResult> {
        let okta_origin = self.base_origin()?;

        for redirects_followed in 0..=MAX_SAML_REDIRECTS {
            let mut request = self.client.get(url.clone()).header(ACCEPT, "text/html");
            if let Some(session_id) = session_id.filter(|_| url.origin() == okta_origin) {
                request = request.header(COOKIE, format!("sid={session_id}"));
            }

            let resp = request.send().await?;
            let status = resp.status();

            if status.is_redirection() {
                if redirects_followed == MAX_SAML_REDIRECTS {
                    return Err(Error::Saml(
                        "too many redirects while fetching SAML assertion".into(),
                    ));
                }

                let location = resp
                    .headers()
                    .get("location")
                    .ok_or_else(|| Error::Saml("missing redirect location header".into()))?
                    .to_str()
                    .map_err(|_| Error::Saml("invalid redirect location header".into()))?;
                url = url.join(location)?;
                if url.origin() != okta_origin {
                    return Err(Error::Saml(
                        "redirected away from validated Okta origin".into(),
                    ));
                }
                debug!("following SAML redirect to {url}");
                continue;
            }

            if !status.is_success() {
                return Err(Error::Saml(format!(
                    "failed to get SAML assertion (HTTP {status})"
                )));
            }

            let html =
                read_response_text(resp, MAX_OKTA_RESPONSE_BYTES, "Okta SAML response").await?;
            return Ok(HtmlFetchResult {
                final_url: url,
                html,
                redirects_followed,
            });
        }

        unreachable!("redirect loop exits within MAX_SAML_REDIRECTS bounds");
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
            username,
            password: password.as_str(),
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
        let text = read_response_text(resp, MAX_OKTA_RESPONSE_BYTES, "Okta authn response").await?;

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
        let text =
            read_response_text(resp, MAX_OKTA_RESPONSE_BYTES, "Okta MFA verify response").await?;

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
        let text =
            read_response_text(resp, MAX_OKTA_RESPONSE_BYTES, "Okta MFA verify response").await?;

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
        timeout: Duration,
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
                        tokio::time::sleep(Duration::from_secs(2)).await;
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
        let url = self.saml_url_with_session_token(app_url, session_token.as_str())?;
        let response = self.fetch_html_following_redirects(url, None).await?;
        extract_saml_assertion(&response.html)
    }

    /// Exchange a one-time session token for a reusable Okta session cookie id.
    pub async fn create_session(&self, session_token: &Zeroizing<String>) -> Result<OktaSession> {
        let url = format!("{}/api/v1/sessions", self.base_url);
        let body = CreateSessionRequest {
            session_token: session_token.as_str().to_owned(),
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
        let text =
            read_response_text(resp, MAX_OKTA_RESPONSE_BYTES, "Okta session response").await?;
        if !status.is_success() {
            let err_msg = parse_okta_error(&text);
            return Err(Error::Auth(format!(
                "Okta session creation failed (HTTP {status}): {err_msg}"
            )));
        }

        let created: CreateSessionResponse = serde_json::from_str(&text)
            .map_err(|e| Error::Auth(format!("bad Okta session response: {e}")))?;

        Ok(OktaSession {
            session_id: created.id,
            expiration: created.expires_at,
        })
    }

    /// Get a SAML assertion using an existing Okta session cookie.
    ///
    /// Used when the Okta session is cached (avoids re-authentication).
    pub async fn get_saml_with_session(&self, session_id: &str, app_url: &str) -> Result<String> {
        let app_url = self.validated_app_url(app_url)?;
        let response = self
            .fetch_html_following_redirects(app_url, Some(session_id))
            .await?;

        match extract_saml_assertion(&response.html) {
            Ok(assertion) => Ok(assertion),
            Err(_extract_error) if response.redirects_followed > 0 => {
                warn!(
                    "Okta session redirect ended without a SAML assertion at {}",
                    response.final_url
                );
                Err(Error::Auth(
                    "Okta session expired or redirected to a non-SAML page".into(),
                ))
            }
            Err(error) => Err(error),
        }
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn build_okta_http_client(timeout: Duration) -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
        .build()?)
}

async fn read_response_text(
    mut response: reqwest::Response,
    max_bytes: usize,
    context: &str,
) -> Result<String> {
    if let Some(content_length) = response.content_length() {
        if content_length > max_bytes as u64 {
            return Err(Error::Auth(format!("{context} exceeds {max_bytes} bytes")));
        }
    }

    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        bytes.extend_from_slice(&chunk);
        if bytes.len() > max_bytes {
            return Err(Error::Auth(format!("{context} exceeds {max_bytes} bytes")));
        }
    }

    String::from_utf8(bytes)
        .map_err(|error| Error::Auth(format!("{context} is not valid UTF-8: {error}")))
}

pub(crate) fn validate_okta_organization(organization: &str) -> Result<String> {
    let organization = organization.trim();
    if organization.is_empty() {
        return Err(Error::Config("okta organization cannot be empty".into()));
    }
    if organization.contains("://")
        || organization.contains('/')
        || organization.contains('?')
        || organization.contains('#')
        || organization.contains('@')
    {
        return Err(Error::Config(format!(
            "okta organization must be a bare host or host:port: {organization}"
        )));
    }

    let parsed = Url::parse(&format!("https://{organization}"))?;
    if parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(Error::Config(format!(
            "okta organization must be a bare host or host:port: {organization}"
        )));
    }

    Ok(organization.to_owned())
}

pub(crate) fn validate_okta_application_url(organization: &str, app_url: &str) -> Result<String> {
    let organization = validate_okta_organization(organization)?;
    let base_url = format!("https://{organization}");
    Ok(validate_okta_app_url_against_base_url(&base_url, app_url)?.to_string())
}

fn validate_okta_app_url_against_base_url(base_url: &str, app_url: &str) -> Result<Url> {
    let base = Url::parse(base_url)?;
    let app = Url::parse(app_url)?;

    if base.scheme() == "https" && app.scheme() != "https" {
        return Err(Error::Config(format!(
            "okta application URL must use HTTPS: {app_url}"
        )));
    }

    if base.origin() != app.origin() {
        return Err(Error::Config(format!(
            "okta application URL must match Okta organization origin {}: {app_url}",
            base.origin().ascii_serialization()
        )));
    }

    Ok(app)
}

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
    let document = Html::parse_document(html);
    let form_selector = Selector::parse("form")
        .map_err(|error| Error::Saml(format!("failed to build HTML selector: {error}")))?;
    let input_selector = Selector::parse("input")
        .map_err(|error| Error::Saml(format!("failed to build HTML selector: {error}")))?;

    let form_candidates: Vec<FormSamlCandidate> = document
        .select(&form_selector)
        .map(|form| form_saml_candidate(form, &input_selector))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect();

    if let Some(assertion) = select_saml_candidate(&form_candidates)? {
        return Ok(assertion);
    }

    let standalone_candidates: Vec<FormSamlCandidate> = document
        .select(&input_selector)
        .filter_map(|input| standalone_saml_candidate(input))
        .collect();
    if let Some(assertion) = select_saml_candidate(&standalone_candidates)? {
        return Ok(assertion);
    }

    Err(Error::Saml(
        "could not find SAMLResponse in Okta HTML response".into(),
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FormSamlCandidate {
    value: String,
    is_aws_post_form: bool,
    has_relay_state: bool,
    is_post_form: bool,
}

fn form_saml_candidate(
    form: scraper::element_ref::ElementRef<'_>,
    input_selector: &Selector,
) -> Result<Option<FormSamlCandidate>> {
    let saml_values: Vec<String> = form
        .select(input_selector)
        .filter_map(saml_input_value)
        .collect();
    if saml_values.len() > 1 {
        return Err(Error::Saml(
            "multiple SAMLResponse inputs found in the same form".into(),
        ));
    }
    let Some(value) = saml_values.into_iter().next() else {
        return Ok(None);
    };
    Ok(Some(FormSamlCandidate {
        value,
        is_aws_post_form: form_posts_to_aws(form.value().attr("action")),
        has_relay_state: form_has_named_input(form, input_selector, "RelayState"),
        is_post_form: form_method_is_post(form.value().attr("method")),
    }))
}

fn standalone_saml_candidate(
    input: scraper::element_ref::ElementRef<'_>,
) -> Option<FormSamlCandidate> {
    Some(FormSamlCandidate {
        value: saml_input_value(input)?,
        is_aws_post_form: false,
        has_relay_state: false,
        is_post_form: false,
    })
}

fn form_has_named_input(
    form: scraper::element_ref::ElementRef<'_>,
    input_selector: &Selector,
    name: &str,
) -> bool {
    form.select(input_selector).any(|input| {
        input
            .value()
            .attr("name")
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(name))
    })
}

fn form_method_is_post(method: Option<&str>) -> bool {
    method.is_some_and(|method| method.eq_ignore_ascii_case("post"))
}

fn saml_input_value(input: scraper::element_ref::ElementRef<'_>) -> Option<String> {
    let attrs = input.value();
    attrs
        .attr("name")
        .filter(|name| name.eq_ignore_ascii_case("SAMLResponse"))
        .and_then(|_| attrs.attr("value"))
        .map(str::to_owned)
}

fn select_saml_candidate(candidates: &[FormSamlCandidate]) -> Result<Option<String>> {
    if candidates.is_empty() {
        return Ok(None);
    }

    let aws_candidates: Vec<&FormSamlCandidate> = candidates
        .iter()
        .filter(|candidate| candidate.is_aws_post_form)
        .collect();
    if aws_candidates.len() == 1 {
        return Ok(Some(aws_candidates[0].value.clone()));
    }
    if aws_candidates.len() > 1 {
        return Err(Error::Saml(
            "multiple AWS SAMLResponse forms found in Okta HTML response".into(),
        ));
    }

    let relay_state_candidates: Vec<&FormSamlCandidate> = candidates
        .iter()
        .filter(|candidate| candidate.has_relay_state && candidate.is_post_form)
        .collect();
    if relay_state_candidates.len() == 1 {
        return Ok(Some(relay_state_candidates[0].value.clone()));
    }
    if relay_state_candidates.len() > 1 {
        return Err(Error::Saml(
            "multiple SAMLResponse POST forms with RelayState found in Okta HTML response".into(),
        ));
    }

    if candidates.len() == 1 {
        return Ok(Some(candidates[0].value.clone()));
    }

    Err(Error::Saml(
        "multiple SAMLResponse candidates found in Okta HTML response".into(),
    ))
}

fn form_posts_to_aws(action: Option<&str>) -> bool {
    let Some(action) = action else {
        return false;
    };
    let Ok(url) = Url::parse(action) else {
        return false;
    };
    matches!(url.host_str(), Some("signin.aws.amazon.com")) && url.path() == "/saml"
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

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
    fn extract_saml_with_single_quotes_and_extra_attributes() {
        let html = r#"<input data-se="1" name='SAMLResponse' data-extra="x" value='base64data' />"#;
        let assertion = extract_saml_assertion(html).unwrap();
        assert_eq!(assertion, "base64data");
    }

    #[test]
    fn extract_saml_with_unquoted_value() {
        let html = r#"<input value=base64data type="hidden" name="SAMLResponse">"#;
        let assertion = extract_saml_assertion(html).unwrap();
        assert_eq!(assertion, "base64data");
    }

    #[test]
    fn extract_saml_ignores_comment_decoys() {
        let html = r#"<!-- <input name="SAMLResponse" value="wrong"> -->
        <form><input type="hidden" name="SAMLResponse" value="correct"></form>"#;
        let assertion = extract_saml_assertion(html).unwrap();
        assert_eq!(assertion, "correct");
    }

    #[test]
    fn extract_saml_ignores_script_decoys() {
        let html = r#"<script>var fake = '<input name="SAMLResponse" value="wrong">';</script>
        <form><input type="hidden" name="SAMLResponse" value="correct"></form>"#;
        let assertion = extract_saml_assertion(html).unwrap();
        assert_eq!(assertion, "correct");
    }

    #[test]
    fn extract_saml_prefers_aws_post_form_over_other_candidates() {
        let html = r#"<html><body>
        <form action="https://example.test/not-aws">
            <input type="hidden" name="SAMLResponse" value="wrong">
        </form>
        <form method="post" action="https://signin.aws.amazon.com/saml">
            <input type="hidden" name="SAMLResponse" value="correct">
        </form>
        </body></html>"#;
        let assertion = extract_saml_assertion(html).unwrap();
        assert_eq!(assertion, "correct");
    }

    #[test]
    fn extract_saml_prefers_unique_post_form_with_relay_state() {
        let html = r#"<html><body>
        <form action="/decoy">
            <input type="hidden" name="SAMLResponse" value="wrong">
        </form>
        <form method="post">
            <input type="hidden" name="SAMLResponse" value="correct">
            <input type="hidden" name="RelayState" value="">
        </form>
        </body></html>"#;
        let assertion = extract_saml_assertion(html).unwrap();
        assert_eq!(assertion, "correct");
    }

    #[test]
    fn extract_saml_rejects_ambiguous_multiple_forms_without_aws_action() {
        let html = r#"<html><body>
        <form><input type="hidden" name="SAMLResponse" value="first"></form>
        <form><input type="hidden" name="SAMLResponse" value="second"></form>
        </body></html>"#;
        let error = extract_saml_assertion(html).unwrap_err();
        assert!(error
            .to_string()
            .contains("multiple SAMLResponse candidates"));
    }

    #[test]
    fn extract_saml_rejects_multiple_saml_inputs_in_same_form() {
        let html = r#"<html><body>
        <form method="post" action="https://signin.aws.amazon.com/saml">
            <input type="hidden" name="SAMLResponse" value="first">
            <input type="hidden" name="SAMLResponse" value="second">
        </form>
        </body></html>"#;
        let error = extract_saml_assertion(html).unwrap_err();
        assert!(error
            .to_string()
            .contains("multiple SAMLResponse inputs found in the same form"));
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
    fn validate_okta_organization_accepts_host() {
        let organization = validate_okta_organization("mycompany.okta.com").unwrap();
        assert_eq!(organization, "mycompany.okta.com");
    }

    #[test]
    fn validate_okta_organization_rejects_path() {
        let error = validate_okta_organization("mycompany.okta.com/home/app").unwrap_err();
        assert!(error.to_string().contains("bare host"));
    }

    #[test]
    fn validate_okta_organization_rejects_userinfo() {
        let error = validate_okta_organization("user@mycompany.okta.com").unwrap_err();
        assert!(error.to_string().contains("bare host"));
    }

    #[test]
    fn validate_okta_application_url_accepts_same_origin_https() {
        let url = validate_okta_application_url(
            "mycompany.okta.com",
            "https://mycompany.okta.com/home/amazon_aws/0oa123/272",
        )
        .unwrap();

        assert_eq!(url, "https://mycompany.okta.com/home/amazon_aws/0oa123/272");
    }

    #[test]
    fn validate_okta_application_url_rejects_cross_origin() {
        let error = validate_okta_application_url(
            "mycompany.okta.com",
            "https://evil.example.com/home/amazon_aws/0oa123/272",
        )
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("must match Okta organization origin"));
    }

    #[test]
    fn validate_okta_application_url_rejects_cleartext() {
        let error = validate_okta_application_url(
            "mycompany.okta.com",
            "http://mycompany.okta.com/home/amazon_aws/0oa123/272",
        )
        .unwrap_err();

        assert!(error.to_string().contains("must use HTTPS"));
    }

    #[test]
    fn saml_url_with_session_token_preserves_existing_query() {
        let client = OktaClient::new("mycompany.okta.com").unwrap();
        let url = client
            .saml_url_with_session_token(
                "https://mycompany.okta.com/home/amazon_aws/0oa123/272?fromHome=true",
                "session-token-123",
            )
            .unwrap();

        assert_eq!(
            url.query(),
            Some("fromHome=true&sessionToken=session-token-123")
        );
    }

    #[tokio::test]
    async fn okta_client_timeout_is_bounded() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/api/v1/authn"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_millis(200))
                    .set_body_json(serde_json::json!({
                        "status": "SUCCESS",
                        "sessionToken": "slow-token"
                    })),
            )
            .expect(1)
            .mount(&server)
            .await;

        let client =
            OktaClient::with_base_url_and_timeout(&server.uri(), Duration::from_millis(50))
                .unwrap();
        let password = Zeroizing::new("password".to_string());
        let error = client
            .authenticate("user@example.com", &password)
            .await
            .unwrap_err();

        assert!(
            matches!(error, Error::Http(_) | Error::Timeout(_)),
            "unexpected error: {error}"
        );
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
