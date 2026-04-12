use std::fmt;
use std::str::FromStr;

use crate::{Error, Result};

/// Supported MFA factor types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MfaFactor {
    Push,
    Totp,
    YubikeyOtp,
}

impl fmt::Display for MfaFactor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Push => write!(f, "push"),
            Self::Totp => write!(f, "totp"),
            Self::YubikeyOtp => write!(f, "yubikey"),
        }
    }
}

impl FromStr for MfaFactor {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "push" => Ok(Self::Push),
            "totp" => Ok(Self::Totp),
            "yubikey" | "yubikey_otp" | "yubikeyotp" | "yubikey-otp" => Ok(Self::YubikeyOtp),
            other => Err(Error::Mfa(format!(
                "unknown MFA factor: {other} (valid: push, totp, yubikey)"
            ))),
        }
    }
}

/// An MFA challenge from Okta's `/api/v1/authn` response.
#[derive(Debug, Clone)]
pub struct MfaChallenge {
    pub factor_id: String,
    pub factor_type: String,
    pub provider: String,
    /// Profile link for push verification (Okta Verify).
    pub profile: Option<String>,
}

/// Select the best matching factor from a list of available challenges.
///
/// If `preferred` is provided, returns the first challenge that matches.
/// Otherwise returns the first available challenge.
pub fn select_factor<'a>(
    factors: &'a [MfaChallenge],
    preferred: Option<&MfaFactor>,
) -> Result<&'a MfaChallenge> {
    if factors.is_empty() {
        return Err(Error::Mfa("no MFA factors available".into()));
    }

    if let Some(pref) = preferred {
        for challenge in factors {
            if factor_matches(challenge, pref) {
                return Ok(challenge);
            }
        }
        return Err(Error::Mfa(format!(
            "preferred factor '{pref}' not available; available factors: {}",
            factors
                .iter()
                .map(|f| format!("{}/{}", f.factor_type, f.provider))
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }

    // No preference: return first available
    Ok(&factors[0])
}

/// Check whether an Okta challenge matches our MFA factor enum.
pub fn factor_matches(challenge: &MfaChallenge, factor: &MfaFactor) -> bool {
    match factor {
        MfaFactor::Push => challenge.factor_type == "push",
        MfaFactor::Totp => challenge.factor_type == "token:software:totp",
        MfaFactor::YubikeyOtp => {
            challenge.factor_type == "token:hardware" && challenge.provider == "YUBICO"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mfa_factor_display() {
        assert_eq!(MfaFactor::Push.to_string(), "push");
        assert_eq!(MfaFactor::Totp.to_string(), "totp");
        assert_eq!(MfaFactor::YubikeyOtp.to_string(), "yubikey");
    }

    #[test]
    fn mfa_factor_from_str() {
        assert_eq!(MfaFactor::from_str("push").unwrap(), MfaFactor::Push);
        assert_eq!(MfaFactor::from_str("PUSH").unwrap(), MfaFactor::Push);
        assert_eq!(MfaFactor::from_str("totp").unwrap(), MfaFactor::Totp);
        assert_eq!(
            MfaFactor::from_str("yubikey").unwrap(),
            MfaFactor::YubikeyOtp
        );
        assert_eq!(
            MfaFactor::from_str("yubikey_otp").unwrap(),
            MfaFactor::YubikeyOtp
        );
        assert_eq!(
            MfaFactor::from_str("yubikey-otp").unwrap(),
            MfaFactor::YubikeyOtp
        );
        assert!(MfaFactor::from_str("unknown").is_err());
    }

    fn make_push_challenge() -> MfaChallenge {
        MfaChallenge {
            factor_id: "push-id".into(),
            factor_type: "push".into(),
            provider: "OKTA".into(),
            profile: Some("https://okta.example.com".into()),
        }
    }

    fn make_totp_challenge() -> MfaChallenge {
        MfaChallenge {
            factor_id: "totp-id".into(),
            factor_type: "token:software:totp".into(),
            provider: "OKTA".into(),
            profile: None,
        }
    }

    fn make_yubikey_challenge() -> MfaChallenge {
        MfaChallenge {
            factor_id: "yubi-id".into(),
            factor_type: "token:hardware".into(),
            provider: "YUBICO".into(),
            profile: None,
        }
    }

    #[test]
    fn factor_matches_push() {
        assert!(factor_matches(&make_push_challenge(), &MfaFactor::Push));
        assert!(!factor_matches(&make_push_challenge(), &MfaFactor::Totp));
    }

    #[test]
    fn factor_matches_totp() {
        assert!(factor_matches(&make_totp_challenge(), &MfaFactor::Totp));
        assert!(!factor_matches(&make_totp_challenge(), &MfaFactor::Push));
    }

    #[test]
    fn factor_matches_yubikey() {
        assert!(factor_matches(
            &make_yubikey_challenge(),
            &MfaFactor::YubikeyOtp
        ));
        assert!(!factor_matches(&make_yubikey_challenge(), &MfaFactor::Push));
    }

    #[test]
    fn select_factor_preferred() {
        let factors = vec![
            make_push_challenge(),
            make_totp_challenge(),
            make_yubikey_challenge(),
        ];

        let selected = select_factor(&factors, Some(&MfaFactor::Totp)).unwrap();
        assert_eq!(selected.factor_id, "totp-id");
    }

    #[test]
    fn select_factor_no_preference() {
        let factors = vec![make_totp_challenge(), make_push_challenge()];
        let selected = select_factor(&factors, None).unwrap();
        assert_eq!(selected.factor_id, "totp-id"); // first one
    }

    #[test]
    fn select_factor_preferred_not_available() {
        let factors = vec![make_push_challenge()];
        let result = select_factor(&factors, Some(&MfaFactor::YubikeyOtp));
        assert!(result.is_err());
    }

    #[test]
    fn select_factor_empty() {
        let factors: Vec<MfaChallenge> = vec![];
        let result = select_factor(&factors, None);
        assert!(result.is_err());
    }
}
