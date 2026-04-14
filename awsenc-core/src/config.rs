use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use url::Url;

use crate::{Error, Result};

// ---------------------------------------------------------------------------
// Global config (loaded from ~/.config/awsenc/config.toml)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GlobalConfig {
    #[serde(default)]
    pub okta: OktaConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default)]
    pub aliases: HashMap<String, String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OktaConfig {
    pub organization: Option<String>,
    pub user: Option<String>,
    pub default_factor: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub biometric: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CacheConfig {
    pub refresh_window_seconds: Option<u64>,
}

// ---------------------------------------------------------------------------
// Per-profile config (loaded from ~/.config/awsenc/profiles/<name>.toml)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProfileConfig {
    #[serde(default)]
    pub okta: ProfileOktaConfig,
    #[serde(default)]
    pub security: ProfileSecurityConfig,
    pub secondary_role: Option<SecondaryRoleConfig>,
    pub region: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProfileOktaConfig {
    pub organization: Option<String>,
    pub user: Option<String>,
    pub application: Option<String>,
    pub role: Option<String>,
    pub factor: Option<String>,
    pub duration: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProfileSecurityConfig {
    pub biometric: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecondaryRoleConfig {
    pub role_arn: String,
}

// ---------------------------------------------------------------------------
// CLI / env overrides
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct ConfigOverrides {
    pub user: Option<String>,
    pub organization: Option<String>,
    pub application: Option<String>,
    pub role: Option<String>,
    pub factor: Option<String>,
    pub duration: Option<u64>,
    pub biometric: Option<bool>,
    pub region: Option<String>,
}

impl ConfigOverrides {
    /// Build overrides from environment variables.
    pub fn from_env() -> Self {
        Self {
            user: std::env::var("AWSENC_OKTA_USER").ok(),
            organization: std::env::var("AWSENC_OKTA_ORG").ok(),
            application: std::env::var("AWSENC_OKTA_APP").ok(),
            role: None,
            factor: std::env::var("AWSENC_FACTOR").ok(),
            duration: None,
            biometric: std::env::var("AWSENC_BIOMETRIC")
                .ok()
                .and_then(|v| v.parse::<bool>().ok()),
            region: std::env::var("AWS_DEFAULT_REGION")
                .ok()
                .or_else(|| std::env::var("AWS_REGION").ok()),
        }
    }
}

// ---------------------------------------------------------------------------
// Resolved config (all layers merged, no Options)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    pub okta_organization: String,
    pub okta_user: String,
    pub okta_application: String,
    pub okta_role: String,
    pub okta_factor: String,
    pub okta_duration: u64,
    pub biometric: bool,
    pub refresh_window_seconds: u64,
    pub secondary_role: Option<String>,
    pub region: Option<String>,
}

// ---------------------------------------------------------------------------
// Directory helpers
// ---------------------------------------------------------------------------

/// Returns `~/.config/awsenc/`, creating it with 0o700 permissions if necessary.
pub fn config_dir() -> Result<PathBuf> {
    let dir = dirs::home_dir()
        .ok_or_else(|| Error::Config("could not determine home directory".into()))?
        .join(".config")
        .join("awsenc");
    ensure_dir(&dir)?;
    Ok(dir)
}

/// Returns `~/.config/awsenc/profiles/`, creating it with 0o700 permissions if necessary.
pub fn profiles_dir() -> Result<PathBuf> {
    let dir = config_dir()?.join("profiles");
    ensure_dir(&dir)?;
    Ok(dir)
}

fn ensure_dir(dir: &PathBuf) -> Result<()> {
    if !dir.exists() {
        std::fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(())
}

/// Validate a profile name used in config files, cache files, and managed block markers.
pub fn validate_profile_name(name: &str) -> Result<String> {
    if name.is_empty() {
        return Err(Error::InvalidProfileName(
            "profile name cannot be empty".into(),
        ));
    }
    if name.len() > 64 {
        return Err(Error::InvalidProfileName(format!(
            "profile name exceeds 64 characters: {name}"
        )));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(Error::InvalidProfileName(format!(
            "profile name contains invalid characters (only alphanumeric, hyphens, underscores allowed): {name}"
        )));
    }
    Ok(name.to_owned())
}

/// Return the path to a profile config file after validating the profile name.
pub fn profile_config_path(name: &str) -> Result<PathBuf> {
    let validated = validate_profile_name(name)?;
    Ok(profiles_dir()?.join(format!("{validated}.toml")))
}

// ---------------------------------------------------------------------------
// Load / save helpers
// ---------------------------------------------------------------------------

/// Load the global config from `~/.config/awsenc/config.toml`.
/// Returns default config if the file does not exist.
pub fn load_global_config() -> Result<GlobalConfig> {
    let path = config_dir()?.join("config.toml");
    if !path.exists() {
        return Ok(GlobalConfig::default());
    }
    let contents = std::fs::read_to_string(&path)?;
    let config: GlobalConfig = toml::from_str(&contents)?;
    Ok(config)
}

/// Save the global config to `~/.config/awsenc/config.toml`.
pub fn save_global_config(config: &GlobalConfig) -> Result<()> {
    let path = config_dir()?.join("config.toml");
    let contents = toml::to_string_pretty(config)?;
    std::fs::write(&path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Load a profile config from `~/.config/awsenc/profiles/<name>.toml`.
pub fn load_profile_config(name: &str) -> Result<ProfileConfig> {
    let path = profile_config_path(name)?;
    if !path.exists() {
        return Err(Error::Config(format!("profile config not found: {name}")));
    }
    let contents = std::fs::read_to_string(&path)?;
    let config: ProfileConfig = toml::from_str(&contents)?;
    Ok(config)
}

/// Save a profile config to `~/.config/awsenc/profiles/<name>.toml`.
pub fn save_profile_config(name: &str, config: &ProfileConfig) -> Result<()> {
    let path = profile_config_path(name)?;
    let contents = toml::to_string_pretty(config)?;
    std::fs::write(&path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Config resolution (CLI > env > profile > global > defaults)
// ---------------------------------------------------------------------------

/// Merge all config layers into a `ResolvedConfig`.
///
/// Precedence: CLI flags (overrides) > per-profile TOML > global TOML > defaults.
/// The `overrides` struct should already include env-var values merged with CLI flags
/// by the caller.
pub fn resolve_config(
    _profile_name: &str,
    global: &GlobalConfig,
    profile: &ProfileConfig,
    overrides: &ConfigOverrides,
) -> Result<ResolvedConfig> {
    let okta_organization = overrides
        .organization
        .clone()
        .or_else(|| profile.okta.organization.clone())
        .or_else(|| global.okta.organization.clone())
        .ok_or_else(|| Error::MissingConfig("okta organization".into()))?;
    validate_okta_organization(&okta_organization)?;

    let okta_user = overrides
        .user
        .clone()
        .or_else(|| profile.okta.user.clone())
        .or_else(|| global.okta.user.clone())
        .ok_or_else(|| Error::MissingConfig("okta user".into()))?;

    let okta_application = overrides
        .application
        .clone()
        .or_else(|| profile.okta.application.clone())
        .ok_or_else(|| Error::MissingConfig("okta application URL".into()))?;
    validate_okta_application(&okta_application, &okta_organization)?;

    let okta_role = overrides
        .role
        .clone()
        .or_else(|| profile.okta.role.clone())
        .ok_or_else(|| Error::MissingConfig("okta role".into()))?;

    let okta_factor = overrides
        .factor
        .clone()
        .or_else(|| profile.okta.factor.clone())
        .or_else(|| global.okta.default_factor.clone())
        .unwrap_or_else(|| "push".to_owned());

    let okta_duration = overrides.duration.or(profile.okta.duration).unwrap_or(3600);

    let biometric = overrides
        .biometric
        .or(profile.security.biometric)
        .or(global.security.biometric)
        .unwrap_or(false);

    let refresh_window_seconds = global.cache.refresh_window_seconds.unwrap_or(600);

    let secondary_role = profile
        .secondary_role
        .as_ref()
        .map(|sr| sr.role_arn.clone());

    let region = overrides.region.clone().or_else(|| profile.region.clone());

    Ok(ResolvedConfig {
        okta_organization,
        okta_user,
        okta_application,
        okta_role,
        okta_factor,
        okta_duration,
        biometric,
        refresh_window_seconds,
        secondary_role,
        region,
    })
}

fn validate_okta_organization(organization: &str) -> Result<()> {
    if organization.is_empty() || organization.len() > 253 {
        return Err(Error::Config(format!(
            "invalid Okta organization host: {organization}"
        )));
    }
    if !organization
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return Err(Error::Config(format!(
            "invalid Okta organization host: {organization}"
        )));
    }
    let url = Url::parse(&format!("https://{organization}"))?;
    let Some(host) = url.host_str() else {
        return Err(Error::Config(format!(
            "invalid Okta organization host: {organization}"
        )));
    };
    if host != organization || !organization.contains('.') {
        return Err(Error::Config(format!(
            "invalid Okta organization host: {organization}"
        )));
    }
    Ok(())
}

fn validate_okta_application(app_url: &str, organization: &str) -> Result<()> {
    let url = Url::parse(app_url)?;
    if url.scheme() != "https" {
        return Err(Error::Config(format!(
            "Okta application URL must use https: {app_url}"
        )));
    }
    let Some(host) = url.host_str() else {
        return Err(Error::Config(format!(
            "Okta application URL must include a host: {app_url}"
        )));
    };
    if host != organization {
        return Err(Error::Config(format!(
            "Okta application host must match Okta organization ({organization}): {app_url}"
        )));
    }
    if url.username() != "" || url.password().is_some() {
        return Err(Error::Config(format!(
            "Okta application URL must not include credentials: {app_url}"
        )));
    }
    Ok(())
}

/// Resolve a potential alias to a profile name.
pub fn resolve_alias(name: &str, global: &GlobalConfig) -> String {
    global
        .aliases
        .get(name)
        .cloned()
        .unwrap_or_else(|| name.to_owned())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn config_overrides_from_env_empty() {
        // Clear relevant env vars to test defaults
        std::env::remove_var("AWSENC_OKTA_USER");
        std::env::remove_var("AWSENC_OKTA_ORG");
        std::env::remove_var("AWSENC_OKTA_APP");
        std::env::remove_var("AWSENC_FACTOR");
        std::env::remove_var("AWSENC_BIOMETRIC");

        let o = ConfigOverrides::from_env();
        assert!(o.user.is_none());
        assert!(o.organization.is_none());
        assert!(o.application.is_none());
        assert!(o.factor.is_none());
        assert!(o.biometric.is_none());
    }

    #[test]
    fn resolve_alias_found() {
        let mut global = GlobalConfig::default();
        global
            .aliases
            .insert("prod".into(), "my-company-production".into());
        assert_eq!(resolve_alias("prod", &global), "my-company-production");
    }

    #[test]
    fn resolve_alias_not_found() {
        let global = GlobalConfig::default();
        assert_eq!(resolve_alias("something", &global), "something");
    }

    #[test]
    fn validate_profile_name_rejects_traversal_and_whitespace() {
        assert!(validate_profile_name("../evil").is_err());
        assert!(validate_profile_name("profile with spaces").is_err());
        assert!(validate_profile_name("line\nbreak").is_err());
        assert!(validate_profile_name("valid_profile-1").is_ok());
    }

    #[test]
    fn resolve_config_all_layers() {
        let global = GlobalConfig {
            okta: OktaConfig {
                organization: Some("global-org.okta.com".into()),
                user: Some("globaluser".into()),
                default_factor: Some("push".into()),
            },
            security: SecurityConfig {
                biometric: Some(true),
            },
            cache: CacheConfig {
                refresh_window_seconds: Some(300),
            },
            aliases: HashMap::new(),
        };

        let profile = ProfileConfig {
            okta: ProfileOktaConfig {
                organization: None,
                user: None,
                application: Some("https://global-org.okta.com/home/amazon_aws/0oa123/272".into()),
                role: Some("arn:aws:iam::123456789012:role/MyRole".into()),
                factor: Some("yubikey".into()),
                duration: Some(7200),
            },
            security: ProfileSecurityConfig::default(),
            secondary_role: None,
            region: None,
        };

        let overrides = ConfigOverrides::default();

        let resolved = resolve_config("test", &global, &profile, &overrides).unwrap();
        assert_eq!(resolved.okta_organization, "global-org.okta.com");
        assert_eq!(resolved.okta_user, "globaluser");
        assert_eq!(resolved.okta_factor, "yubikey"); // profile overrides global
        assert_eq!(resolved.okta_duration, 7200);
        assert!(resolved.biometric);
        assert_eq!(resolved.refresh_window_seconds, 300);
    }

    #[test]
    fn resolve_config_overrides_take_priority() {
        let global = GlobalConfig {
            okta: OktaConfig {
                organization: Some("global-org.okta.com".into()),
                user: Some("globaluser".into()),
                default_factor: Some("push".into()),
            },
            ..Default::default()
        };

        let profile = ProfileConfig {
            okta: ProfileOktaConfig {
                organization: None,
                user: None,
                application: Some("https://global-org.okta.com/app".into()),
                role: Some("arn:aws:iam::123:role/R".into()),
                factor: Some("yubikey".into()),
                duration: None,
            },
            security: ProfileSecurityConfig::default(),
            secondary_role: None,
            region: None,
        };

        let overrides = ConfigOverrides {
            factor: Some("totp".into()),
            duration: Some(900),
            ..Default::default()
        };

        let resolved = resolve_config("test", &global, &profile, &overrides).unwrap();
        assert_eq!(resolved.okta_factor, "totp"); // override beats profile
        assert_eq!(resolved.okta_duration, 900);
    }

    #[test]
    fn resolve_config_missing_required() {
        let global = GlobalConfig::default();
        let profile = ProfileConfig::default();
        let overrides = ConfigOverrides::default();

        let result = resolve_config("test", &global, &profile, &overrides);
        assert!(result.is_err());
    }

    #[test]
    fn resolve_config_profile_values_fill_user_biometric_and_region() {
        let global = GlobalConfig {
            okta: OktaConfig {
                organization: Some("global-org.okta.com".into()),
                user: Some("global-user".into()),
                default_factor: Some("push".into()),
            },
            security: SecurityConfig {
                biometric: Some(false),
            },
            ..Default::default()
        };

        let profile = ProfileConfig {
            okta: ProfileOktaConfig {
                organization: None,
                user: Some("profile-user".into()),
                application: Some("https://global-org.okta.com/home/amazon_aws/0oa123/272".into()),
                role: Some("arn:aws:iam::123456789012:role/MyRole".into()),
                factor: None,
                duration: None,
            },
            security: ProfileSecurityConfig {
                biometric: Some(true),
            },
            secondary_role: None,
            region: Some("us-west-2".into()),
        };

        let resolved =
            resolve_config("test", &global, &profile, &ConfigOverrides::default()).unwrap();
        assert_eq!(resolved.okta_user, "profile-user");
        assert!(resolved.biometric);
        assert_eq!(resolved.region.as_deref(), Some("us-west-2"));
    }

    #[test]
    fn resolve_config_rejects_invalid_okta_organization() {
        let global = GlobalConfig {
            okta: OktaConfig {
                organization: Some("https://evil.example".into()),
                user: Some("jane".into()),
                default_factor: Some("push".into()),
            },
            ..Default::default()
        };
        let profile = ProfileConfig {
            okta: ProfileOktaConfig {
                application: Some("https://evil.example/app".into()),
                role: Some("arn:aws:iam::123:role/R".into()),
                ..Default::default()
            },
            ..Default::default()
        };

        let err =
            resolve_config("test", &global, &profile, &ConfigOverrides::default()).unwrap_err();
        assert!(err.to_string().contains("invalid Okta organization host"));
    }

    #[test]
    fn resolve_config_rejects_cross_domain_okta_application() {
        let global = GlobalConfig {
            okta: OktaConfig {
                organization: Some("global-org.okta.com".into()),
                user: Some("jane".into()),
                default_factor: Some("push".into()),
            },
            ..Default::default()
        };
        let profile = ProfileConfig {
            okta: ProfileOktaConfig {
                application: Some("https://attacker.example/app".into()),
                role: Some("arn:aws:iam::123:role/R".into()),
                ..Default::default()
            },
            ..Default::default()
        };

        let err =
            resolve_config("test", &global, &profile, &ConfigOverrides::default()).unwrap_err();
        assert!(err
            .to_string()
            .contains("Okta application host must match Okta organization"));
    }

    #[test]
    fn global_config_roundtrip_toml() {
        let mut config = GlobalConfig::default();
        config.okta.organization = Some("my-org.okta.com".into());
        config.okta.user = Some("jane".into());
        config.aliases.insert("p".into(), "production".into());

        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: GlobalConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.okta.organization.as_deref(), Some("my-org.okta.com"));
        assert_eq!(
            parsed.aliases.get("p").map(String::as_str),
            Some("production")
        );
    }

    #[test]
    fn profile_config_roundtrip_toml() {
        let config = ProfileConfig {
            okta: ProfileOktaConfig {
                organization: None,
                user: Some("jane".into()),
                application: Some("https://org.okta.com/app".into()),
                role: Some("arn:aws:iam::123:role/R".into()),
                factor: None,
                duration: Some(3600),
            },
            security: ProfileSecurityConfig {
                biometric: Some(true),
            },
            secondary_role: Some(SecondaryRoleConfig {
                role_arn: "arn:aws:iam::456:role/S".into(),
            }),
            region: Some("us-west-2".into()),
        };

        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: ProfileConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(
            parsed.okta.application.as_deref(),
            Some("https://org.okta.com/app")
        );
        assert_eq!(
            parsed
                .secondary_role
                .as_ref()
                .map(|sr| sr.role_arn.as_str()),
            Some("arn:aws:iam::456:role/S")
        );
        assert_eq!(parsed.okta.user.as_deref(), Some("jane"));
        assert_eq!(parsed.security.biometric, Some(true));
        assert_eq!(parsed.region.as_deref(), Some("us-west-2"));
    }

    #[test]
    fn config_dir_returns_path() {
        // Just verify it produces a path without error
        let dir = config_dir().unwrap();
        assert!(dir.ends_with("awsenc"));
    }

    #[test]
    fn profiles_dir_returns_path() {
        let dir = profiles_dir().unwrap();
        assert!(dir.ends_with("profiles"));
    }
}
