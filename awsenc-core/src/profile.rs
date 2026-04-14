use chrono::{DateTime, TimeZone, Utc};

use crate::cache;
use crate::config;
use crate::credential::CredentialState;
use crate::{Error, Result};

/// Summary information about a configured profile.
#[derive(Debug, Clone)]
pub struct ProfileInfo {
    pub name: String,
    pub has_config: bool,
    pub cache_state: Option<CredentialState>,
    pub expiration: Option<DateTime<Utc>>,
    pub okta_session_expiration: Option<DateTime<Utc>>,
}

/// List all configured profiles by scanning the profiles directory for `.toml` files.
/// Also reads cache headers to determine credential status.
pub fn list_profiles() -> Result<Vec<ProfileInfo>> {
    let profiles_dir = config::profiles_dir()?;
    let mut profiles = Vec::new();

    if !profiles_dir.exists() {
        return Ok(profiles);
    }

    let entries = std::fs::read_dir(&profiles_dir)?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        let is_toml = path.extension().is_some_and(|ext| ext == "toml");

        if !is_toml {
            continue;
        }

        let name = path.file_stem().and_then(|s| s.to_str()).map(String::from);

        let Some(name) = name else {
            continue;
        };

        // Read cache header if available
        let (cache_state, expiration, okta_session_expiration) =
            match cache::read_cache_header(&name) {
                Ok(Some(header)) => {
                    let exp_dt = i64::try_from(header.credential_expiration)
                        .ok()
                        .and_then(|ts| match Utc.timestamp_opt(ts, 0) {
                            chrono::LocalResult::Single(dt) => Some(dt),
                            _ => None,
                        });

                    let state = exp_dt.map(|dt| CredentialState::from_expiration(dt, 600));

                    let okta_exp = if header.has_okta_session() {
                        i64::try_from(header.okta_session_expiration)
                            .ok()
                            .and_then(|ts| match Utc.timestamp_opt(ts, 0) {
                                chrono::LocalResult::Single(dt) => Some(dt),
                                _ => None,
                            })
                    } else {
                        None
                    };

                    (state, exp_dt, okta_exp)
                }
                _ => (None, None, None),
            };

        profiles.push(ProfileInfo {
            name,
            has_config: true,
            cache_state,
            expiration,
            okta_session_expiration,
        });
    }

    profiles.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(profiles)
}

/// Check if a profile config file exists.
pub fn profile_exists(name: &str) -> bool {
    config::profile_config_path(name)
        .map(|path| path.exists())
        .unwrap_or(false)
}

/// Delete a profile's config and cache files.
pub fn delete_profile(name: &str) -> Result<()> {
    // Delete profile config
    let config_path = config::profile_config_path(name)?;
    if config_path.exists() {
        std::fs::remove_file(&config_path)?;
    } else {
        return Err(Error::Profile(format!("profile not found: {name}")));
    }

    // Delete cache file (ignore errors if it doesn't exist)
    drop(cache::delete_cache(name));

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::config::{ProfileConfig, ProfileOktaConfig};

    #[test]
    fn profile_exists_returns_false_for_missing() {
        assert!(!profile_exists("nonexistent-profile-xyz-12345"));
    }

    #[test]
    fn list_profiles_returns_empty_for_new_install() {
        // This test relies on the profiles directory existing but potentially
        // being empty. It should at minimum not error.
        let result = list_profiles();
        assert!(result.is_ok());
    }

    #[test]
    fn profile_info_fields() {
        let info = ProfileInfo {
            name: "test-profile".into(),
            has_config: true,
            cache_state: Some(CredentialState::Fresh),
            expiration: Some(Utc::now() + chrono::Duration::hours(1)),
            okta_session_expiration: Some(Utc::now() + chrono::Duration::hours(2)),
        };

        assert_eq!(info.name, "test-profile");
        assert!(info.has_config);
        assert_eq!(info.cache_state, Some(CredentialState::Fresh));
        assert!(info.expiration.is_some());
        assert!(info.okta_session_expiration.is_some());
    }

    #[test]
    fn roundtrip_profile_config_and_check_exists() {
        let _lock = crate::TEST_ENV_MUTEX.lock().expect("mutex poisoned");
        let tmp = tempfile::tempdir().unwrap();
        let prev_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", tmp.path());

        // Create a temp profile, verify it exists, then clean up
        let name = "test-roundtrip-profile-awsenc";
        let config = ProfileConfig {
            okta: ProfileOktaConfig {
                organization: None,
                application: Some("https://org.okta.com/app".into()),
                role: Some("arn:aws:iam::123:role/R".into()),
                factor: None,
                duration: None,
            },
            region: Some("us-west-1".into()),
            secondary_role: None,
        };

        // Save
        config::save_profile_config(name, &config).unwrap();
        assert!(profile_exists(name));

        // List should include it
        let profiles = list_profiles().unwrap();
        assert!(profiles.iter().any(|p| p.name == name));

        // Delete
        delete_profile(name).unwrap();
        assert!(!profile_exists(name));
        match prev_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn delete_nonexistent_profile_errors() {
        let result = delete_profile("definitely-does-not-exist-xyz");
        assert!(result.is_err());
    }

    #[test]
    fn invalid_profile_name_is_rejected_consistently() {
        assert!(!profile_exists("../escape"));
        assert!(delete_profile("../escape").is_err());
    }
}
