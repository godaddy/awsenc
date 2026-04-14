use base64::Engine;
use chrono::{DateTime, Utc};
use roxmltree::{Document, Node};
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
            let error_msg = find_text_by_local_name(&body, "Message")
                .or_else(|| find_text_by_local_name(&body, "Error"))
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
    let access_key_id = find_text_by_local_name(xml, "AccessKeyId")
        .ok_or_else(|| Error::Sts("missing AccessKeyId in STS response".into()))?;

    let secret_access_key = find_text_by_local_name(xml, "SecretAccessKey")
        .ok_or_else(|| Error::Sts("missing SecretAccessKey in STS response".into()))?;

    let session_token = find_text_by_local_name(xml, "SessionToken")
        .ok_or_else(|| Error::Sts("missing SessionToken in STS response".into()))?;

    let expiration_str = find_text_by_local_name(xml, "Expiration")
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

fn find_text_by_local_name(xml: &str, tag: &str) -> Option<String> {
    let doc = Document::parse(xml).ok()?;
    doc.descendants()
        .find(|node| node.is_element() && node.tag_name().name() == tag)
        .and_then(text_content)
        .map(str::to_owned)
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
    let doc =
        Document::parse(&decoded).map_err(|e| Error::Saml(format!("invalid SAML XML: {e}")))?;
    let mut roles = Vec::new();
    let mut found_role_attribute = false;

    for attribute in doc.descendants().filter(|node| {
        node.is_element()
            && node.tag_name().name() == "Attribute"
            && node.attribute("Name")
                == Some("https://aws.amazon.com/SAML/Attributes/Role")
    }) {
        found_role_attribute = true;
        for value_node in attribute
            .children()
            .filter(|node| node.is_element() && node.tag_name().name() == "AttributeValue")
        {
            let Some(value) = text_content(value_node).map(str::trim) else {
                continue;
            };
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
    }

    if !found_role_attribute {
        return Err(Error::Saml("no Role attribute found in SAML assertion".into()));
    }

    if roles.is_empty() {
        return Err(Error::Saml("no roles found in SAML assertion".into()));
    }

    Ok(roles)
}

fn text_content<'input>(node: Node<'input, 'input>) -> Option<&'input str> {
    node.text().or_else(|| {
        if node.children().all(|child| !child.is_text() && !child.is_element()) {
            Some("")
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn extract_xml_tag_found() {
        let xml = "<Root><AccessKeyId>AKIAIOSFODNN7EXAMPLE</AccessKeyId></Root>";
        assert_eq!(
            find_text_by_local_name(xml, "AccessKeyId"),
            Some("AKIAIOSFODNN7EXAMPLE".to_owned())
        );
    }

    #[test]
    fn extract_xml_tag_not_found() {
        let xml = "<Root><Other>value</Other></Root>";
        assert_eq!(find_text_by_local_name(xml, "AccessKeyId"), None);
    }

    #[test]
    fn extract_xml_tag_empty() {
        let xml = "<Root><AccessKeyId></AccessKeyId></Root>";
        assert_eq!(find_text_by_local_name(xml, "AccessKeyId"), Some(String::new()));
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
    fn parse_assume_role_response_with_namespace() {
        let xml = r#"
            <AssumeRoleWithSAMLResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
                <AssumeRoleWithSAMLResult>
                    <Credentials>
                        <AccessKeyId>ASIAXMLNS</AccessKeyId>
                        <SecretAccessKey>secret</SecretAccessKey>
                        <SessionToken>token</SessionToken>
                        <Expiration>2026-04-11T16:30:00Z</Expiration>
                    </Credentials>
                </AssumeRoleWithSAMLResult>
            </AssumeRoleWithSAMLResponse>
        "#;

        let creds = parse_assume_role_response(xml).unwrap();
        assert_eq!(creds.access_key_id, "ASIAXMLNS");
    }

    #[test]
    fn parse_saml_roles_handles_namespaced_attributes() {
        let saml_xml = r#"<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol">
            <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
                <saml2:AttributeStatement>
                    <saml2:Attribute Name="https://aws.amazon.com/SAML/Attributes/Role">
                        <saml2:AttributeValue>
                            arn:aws:iam::123456789012:saml-provider/Okta,arn:aws:iam::123456789012:role/Admin
                        </saml2:AttributeValue>
                    </saml2:Attribute>
                </saml2:AttributeStatement>
            </saml2:Assertion>
        </saml2p:Response>"#;

        let b64 = base64::engine::general_purpose::STANDARD.encode(saml_xml);
        let roles = parse_saml_roles(&b64).unwrap();
        assert_eq!(roles[0].role_arn, "arn:aws:iam::123456789012:role/Admin");
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
