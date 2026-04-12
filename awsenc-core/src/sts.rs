use base64::Engine;
use chrono::{DateTime, Utc};
use regex::Regex;
use tracing::debug;
use zeroize::Zeroizing;

use crate::credential::AwsCredentials;
use crate::{Error, Result};

/// A role+principal ARN pair extracted from a SAML assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamlRole {
    pub role_arn: String,
    pub principal_arn: String,
}

/// AWS STS client for `AssumeRoleWithSAML`.
#[derive(Debug)]
pub struct StsClient {
    client: reqwest::Client,
    endpoint_url: String,
}

impl StsClient {
    /// Create a new STS client with the default endpoint.
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
            endpoint_url: "https://sts.amazonaws.com".to_owned(),
        }
    }

    /// Create a new STS client with a custom endpoint URL (for testing).
    pub fn with_endpoint(endpoint_url: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            endpoint_url: endpoint_url.to_owned(),
        }
    }

    /// Assume an AWS role using a SAML assertion.
    pub async fn assume_role_with_saml(
        &self,
        role_arn: &str,
        principal_arn: &str,
        saml_assertion: &str,
        duration_seconds: u64,
    ) -> Result<AwsCredentials> {
        debug!("assuming role {role_arn} with principal {principal_arn}");

        let params = [
            ("Action", "AssumeRoleWithSAML"),
            ("Version", "2011-06-15"),
            ("RoleArn", role_arn),
            ("PrincipalArn", principal_arn),
            ("SAMLAssertion", saml_assertion),
        ];

        let resp = self
            .client
            .post(&self.endpoint_url)
            .form(&params)
            .query(&[("DurationSeconds", &duration_seconds.to_string())])
            .send()
            .await?;

        let status = resp.status();
        let body = resp.text().await?;

        if !status.is_success() {
            let error_msg = extract_xml_tag(&body, "Message")
                .or_else(|| extract_xml_tag(&body, "Error"))
                .unwrap_or_else(|| body.chars().take(500).collect());
            return Err(Error::Sts(format!(
                "AssumeRoleWithSAML failed (HTTP {status}): {error_msg}"
            )));
        }

        parse_assume_role_response(&body)
    }
}

impl Default for StsClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse the `AssumeRoleWithSAML` XML response into `AwsCredentials`.
fn parse_assume_role_response(xml: &str) -> Result<AwsCredentials> {
    let access_key_id = extract_xml_tag(xml, "AccessKeyId")
        .ok_or_else(|| Error::Sts("missing AccessKeyId in STS response".into()))?;

    let secret_access_key = extract_xml_tag(xml, "SecretAccessKey")
        .ok_or_else(|| Error::Sts("missing SecretAccessKey in STS response".into()))?;

    let session_token = extract_xml_tag(xml, "SessionToken")
        .ok_or_else(|| Error::Sts("missing SessionToken in STS response".into()))?;

    let expiration_str = extract_xml_tag(xml, "Expiration")
        .ok_or_else(|| Error::Sts("missing Expiration in STS response".into()))?;

    let expiration: DateTime<Utc> = expiration_str
        .parse()
        .map_err(|e| Error::Sts(format!("invalid Expiration timestamp: {e}")))?;

    Ok(AwsCredentials {
        access_key_id,
        secret_access_key: Zeroizing::new(secret_access_key),
        session_token: Zeroizing::new(session_token),
        expiration,
    })
}

/// Extract the text content of an XML tag using regex.
///
/// This is intentionally simple -- the STS response format is predictable and
/// adding a full XML parser dependency is unnecessary.
fn extract_xml_tag(xml: &str, tag: &str) -> Option<String> {
    let pattern = format!("<{tag}>([^<]*)</{tag}>");
    let re = Regex::new(&pattern).ok()?;
    re.captures(xml).map(|caps| caps[1].to_owned())
}

/// Parse available roles from a base64-encoded SAML assertion.
///
/// The SAML assertion contains an `Attribute` element with `Name` =
/// `https://aws.amazon.com/SAML/Attributes/Role`. Each `AttributeValue`
/// contains a comma-separated pair: `<role_arn>,<principal_arn>` (the order
/// can also be `<principal_arn>,<role_arn>`).
pub fn parse_saml_roles(saml_assertion: &str) -> Result<Vec<SamlRole>> {
    let decoded_bytes = base64::engine::general_purpose::STANDARD.decode(saml_assertion)?;
    let decoded = String::from_utf8(decoded_bytes)
        .map_err(|e| Error::Saml(format!("SAML assertion is not valid UTF-8: {e}")))?;

    // Extract the Role attribute values from the SAML XML.
    // The attribute looks like:
    //   <Attribute Name="https://aws.amazon.com/SAML/Attributes/Role">
    //     <AttributeValue>arn:aws:iam::123:role/Role,arn:aws:iam::123:saml-provider/Okta</AttributeValue>
    //   </Attribute>
    let re = Regex::new(r"<(?:\w+:)?AttributeValue[^>]*>([^<]*)</(?:\w+:)?AttributeValue>")?;

    // Find the Role attribute block
    let role_attr_re = Regex::new(
        r#"(?s)<(?:\w+:)?Attribute[^>]+Name\s*=\s*"https://aws\.amazon\.com/SAML/Attributes/Role"[^>]*>(.*?)</(?:\w+:)?Attribute>"#,
    )?;

    let role_block = role_attr_re
        .captures(&decoded)
        .ok_or_else(|| Error::Saml("no Role attribute found in SAML assertion".into()))?;

    let block_text = &role_block[1];
    let mut roles = Vec::new();

    for caps in re.captures_iter(block_text) {
        let value = caps[1].trim();
        if value.is_empty() {
            continue;
        }

        let parts: Vec<&str> = value.split(',').collect();
        if parts.len() != 2 {
            debug!("skipping malformed role attribute value: {value}");
            continue;
        }

        let (role_arn, principal_arn) = if parts[0].contains(":role/") {
            (parts[0].trim().to_owned(), parts[1].trim().to_owned())
        } else {
            (parts[1].trim().to_owned(), parts[0].trim().to_owned())
        };

        roles.push(SamlRole {
            role_arn,
            principal_arn,
        });
    }

    if roles.is_empty() {
        return Err(Error::Saml("no roles found in SAML assertion".into()));
    }

    Ok(roles)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn extract_xml_tag_found() {
        let xml = "<Root><AccessKeyId>AKIAIOSFODNN7EXAMPLE</AccessKeyId></Root>";
        assert_eq!(
            extract_xml_tag(xml, "AccessKeyId"),
            Some("AKIAIOSFODNN7EXAMPLE".to_owned())
        );
    }

    #[test]
    fn extract_xml_tag_not_found() {
        let xml = "<Root><Other>value</Other></Root>";
        assert_eq!(extract_xml_tag(xml, "AccessKeyId"), None);
    }

    #[test]
    fn extract_xml_tag_empty() {
        let xml = "<Root><AccessKeyId></AccessKeyId></Root>";
        assert_eq!(extract_xml_tag(xml, "AccessKeyId"), Some(String::new()));
    }

    #[test]
    fn parse_assume_role_response_success() {
        let xml = r"
            <AssumeRoleWithSAMLResponse>
                <AssumeRoleWithSAMLResult>
                    <Credentials>
                        <AccessKeyId>ASIATESTKEYID</AccessKeyId>
                        <SecretAccessKey>testsecretkey</SecretAccessKey>
                        <SessionToken>testsessiontoken</SessionToken>
                        <Expiration>2026-04-11T16:30:00Z</Expiration>
                    </Credentials>
                </AssumeRoleWithSAMLResult>
            </AssumeRoleWithSAMLResponse>
        ";

        let creds = parse_assume_role_response(xml).unwrap();
        assert_eq!(creds.access_key_id, "ASIATESTKEYID");
        assert_eq!(creds.secret_access_key.as_str(), "testsecretkey");
        assert_eq!(creds.session_token.as_str(), "testsessiontoken");
    }

    #[test]
    fn parse_assume_role_response_missing_field() {
        let xml = r"
            <AssumeRoleWithSAMLResponse>
                <AssumeRoleWithSAMLResult>
                    <Credentials>
                        <AccessKeyId>ASIATESTKEYID</AccessKeyId>
                    </Credentials>
                </AssumeRoleWithSAMLResult>
            </AssumeRoleWithSAMLResponse>
        ";

        assert!(parse_assume_role_response(xml).is_err());
    }

    #[test]
    fn parse_saml_roles_success() {
        // Build a minimal SAML assertion with role attributes
        let saml_xml = r#"<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol">
            <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
                <saml2:AttributeStatement>
                    <saml2:Attribute Name="https://aws.amazon.com/SAML/Attributes/Role">
                        <saml2:AttributeValue>arn:aws:iam::123456789012:role/Admin,arn:aws:iam::123456789012:saml-provider/Okta</saml2:AttributeValue>
                        <saml2:AttributeValue>arn:aws:iam::987654321098:role/ReadOnly,arn:aws:iam::987654321098:saml-provider/Okta</saml2:AttributeValue>
                    </saml2:Attribute>
                </saml2:AttributeStatement>
            </saml2:Assertion>
        </saml2p:Response>"#;

        let b64 = base64::engine::general_purpose::STANDARD.encode(saml_xml);
        let roles = parse_saml_roles(&b64).unwrap();

        assert_eq!(roles.len(), 2);
        assert_eq!(roles[0].role_arn, "arn:aws:iam::123456789012:role/Admin");
        assert_eq!(
            roles[0].principal_arn,
            "arn:aws:iam::123456789012:saml-provider/Okta"
        );
        assert_eq!(roles[1].role_arn, "arn:aws:iam::987654321098:role/ReadOnly");
    }

    #[test]
    fn parse_saml_roles_reversed_order() {
        let saml_xml = r#"<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol">
            <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
                <saml2:AttributeStatement>
                    <saml2:Attribute Name="https://aws.amazon.com/SAML/Attributes/Role">
                        <saml2:AttributeValue>arn:aws:iam::111:saml-provider/Okta,arn:aws:iam::111:role/Dev</saml2:AttributeValue>
                    </saml2:Attribute>
                </saml2:AttributeStatement>
            </saml2:Assertion>
        </saml2p:Response>"#;

        let b64 = base64::engine::general_purpose::STANDARD.encode(saml_xml);
        let roles = parse_saml_roles(&b64).unwrap();

        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].role_arn, "arn:aws:iam::111:role/Dev");
        assert_eq!(
            roles[0].principal_arn,
            "arn:aws:iam::111:saml-provider/Okta"
        );
    }

    #[test]
    fn parse_saml_roles_no_roles() {
        let saml_xml = r#"<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol">
            <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
                <saml2:AttributeStatement>
                    <saml2:Attribute Name="https://aws.amazon.com/SAML/Attributes/SessionDuration">
                        <saml2:AttributeValue>3600</saml2:AttributeValue>
                    </saml2:Attribute>
                </saml2:AttributeStatement>
            </saml2:Assertion>
        </saml2p:Response>"#;

        let b64 = base64::engine::general_purpose::STANDARD.encode(saml_xml);
        assert!(parse_saml_roles(&b64).is_err());
    }

    #[test]
    fn parse_saml_roles_bad_base64() {
        assert!(parse_saml_roles("not-valid-base64!!!").is_err());
    }

    #[test]
    fn sts_client_default() {
        let client = StsClient::new();
        assert_eq!(client.endpoint_url, "https://sts.amazonaws.com");
    }

    #[test]
    fn sts_client_custom_endpoint() {
        let client = StsClient::with_endpoint("http://localhost:4566");
        assert_eq!(client.endpoint_url, "http://localhost:4566");
    }
}
