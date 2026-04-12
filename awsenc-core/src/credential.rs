use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

/// AWS temporary credentials obtained from STS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsCredentials {
    pub access_key_id: String,
    #[serde(
        serialize_with = "serialize_zeroizing",
        deserialize_with = "deserialize_zeroizing"
    )]
    pub secret_access_key: Zeroizing<String>,
    #[serde(
        serialize_with = "serialize_zeroizing",
        deserialize_with = "deserialize_zeroizing"
    )]
    pub session_token: Zeroizing<String>,
    pub expiration: DateTime<Utc>,
}

impl Drop for AwsCredentials {
    fn drop(&mut self) {
        self.access_key_id.zeroize();
    }
}

/// Output format for the AWS CLI `credential_process` protocol.
#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct CredentialProcessOutput {
    pub version: u32,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    pub expiration: String,
}

impl CredentialProcessOutput {
    /// Create the `credential_process` JSON output from `AwsCredentials`.
    pub fn from_credentials(creds: &AwsCredentials) -> Self {
        Self {
            version: 1,
            access_key_id: creds.access_key_id.clone(),
            secret_access_key: creds.secret_access_key.as_str().to_owned(),
            session_token: creds.session_token.as_str().to_owned(),
            expiration: creds.expiration.to_rfc3339(),
        }
    }
}

/// Represents how close a cached credential is to expiration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialState {
    /// More than `refresh_window_secs` remaining.
    Fresh,
    /// Less than `refresh_window_secs` remaining but not yet expired.
    Refresh,
    /// Past expiration.
    Expired,
}

impl CredentialState {
    /// Determine credential state from an expiration timestamp and a refresh window.
    pub fn from_expiration(expiration: DateTime<Utc>, refresh_window_secs: i64) -> Self {
        let now = Utc::now();
        if now >= expiration {
            Self::Expired
        } else {
            let remaining = expiration.signed_duration_since(now);
            if remaining.num_seconds() <= refresh_window_secs {
                Self::Refresh
            } else {
                Self::Fresh
            }
        }
    }
}

impl std::fmt::Display for CredentialState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fresh => write!(f, "fresh"),
            Self::Refresh => write!(f, "refresh"),
            Self::Expired => write!(f, "expired"),
        }
    }
}

fn serialize_zeroizing<S>(value: &Zeroizing<String>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(value.as_str())
}

fn deserialize_zeroizing<'de, D>(deserializer: D) -> Result<Zeroizing<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Ok(Zeroizing::new(s))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use chrono::TimeZone;

    #[test]
    fn credential_state_fresh() {
        let expiration = Utc::now() + chrono::Duration::seconds(1200);
        let state = CredentialState::from_expiration(expiration, 600);
        assert_eq!(state, CredentialState::Fresh);
    }

    #[test]
    fn credential_state_refresh() {
        let expiration = Utc::now() + chrono::Duration::seconds(300);
        let state = CredentialState::from_expiration(expiration, 600);
        assert_eq!(state, CredentialState::Refresh);
    }

    #[test]
    fn credential_state_expired() {
        let expiration = Utc::now() - chrono::Duration::seconds(10);
        let state = CredentialState::from_expiration(expiration, 600);
        assert_eq!(state, CredentialState::Expired);
    }

    #[test]
    fn credential_process_output_format() {
        let creds = AwsCredentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_owned(),
            secret_access_key: Zeroizing::new(
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_owned(),
            ),
            session_token: Zeroizing::new("FwoGZXIvYXdzEBYaDH...".to_owned()),
            expiration: Utc.with_ymd_and_hms(2026, 4, 11, 16, 30, 0).unwrap(),
        };
        let output = CredentialProcessOutput::from_credentials(&creds);
        assert_eq!(output.version, 1);
        assert_eq!(output.access_key_id, "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(
            output.secret_access_key,
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        );

        let json = serde_json::to_value(&output).unwrap();
        assert_eq!(json["Version"], 1);
        assert!(json["AccessKeyId"].is_string());
        assert!(json["Expiration"].is_string());
    }

    #[test]
    fn credential_roundtrip_serde() {
        let creds = AwsCredentials {
            access_key_id: "AKID".to_owned(),
            secret_access_key: Zeroizing::new("secret".to_owned()),
            session_token: Zeroizing::new("token".to_owned()),
            expiration: Utc::now(),
        };
        let json = serde_json::to_string(&creds).unwrap();
        let deserialized: AwsCredentials = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.access_key_id, creds.access_key_id);
        assert_eq!(*deserialized.secret_access_key, *creds.secret_access_key);
        assert_eq!(*deserialized.session_token, *creds.session_token);
    }

    #[test]
    fn credential_state_display() {
        assert_eq!(CredentialState::Fresh.to_string(), "fresh");
        assert_eq!(CredentialState::Refresh.to_string(), "refresh");
        assert_eq!(CredentialState::Expired.to_string(), "expired");
    }
}
