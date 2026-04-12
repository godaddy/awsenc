use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

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
    pub secondary_role: Option<SecondaryRoleConfig>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProfileOktaConfig {
    pub organization: Option<String>,
    pub application: Option<String>,
    pub role: Option<String>,
    pub factor: Option<String>,
    pub duration: Option<u64>,
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
            region: None,
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

/// Load a profile config from `~/.config/awsenc/profiles/<name>.toml`.
pub fn load_profile_config(name: &str) -> Result<ProfileConfig> {
    let path = profiles_dir()?.join(format!("{name}.toml"));
    if !path.exists() {
        return Err(Error::Config(format!("profile config not found: {name}")));
    }
    let contents = std::fs::read_to_string(&path)?;
    let config: ProfileConfig = toml::from_str(&contents)?;
    Ok(config)
}

/// Save a profile config to `~/.config/awsenc/profiles/<name>.toml`.
pub fn save_profile_config(name: &str, config: &ProfileConfig) -> Result<()> {
    let dir = profiles_dir()?;
    let path = dir.join(format!("{name}.toml"));
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

    let okta_user = overrides
        .user
        .clone()
        .or_else(|| global.okta.user.clone())
        .ok_or_else(|| Error::MissingConfig("okta user".into()))?;

    let okta_application = overrides
        .application
        .clone()
        .or_else(|| profile.okta.application.clone())
        .ok_or_else(|| Error::MissingConfig("okta application URL".into()))?;

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
        .or(global.security.biometric)
        .unwrap_or(false);

    let refresh_window_seconds = global.cache.refresh_window_seconds.unwrap_or(600);

    let secondary_role = profile
        .secondary_role
        .as_ref()
        .map(|sr| sr.role_arn.clone());

    let region = overrides.region.clone();

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
                application: Some("https://org.okta.com/home/amazon_aws/0oa123/272".into()),
                role: Some("arn:aws:iam::123456789012:role/MyRole".into()),
                factor: Some("yubikey".into()),
                duration: Some(7200),
            },
            secondary_role: None,
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
                application: Some("https://org.okta.com/app".into()),
                role: Some("arn:aws:iam::123:role/R".into()),
                factor: Some("yubikey".into()),
                duration: None,
            },
            secondary_role: None,
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
                application: Some("https://org.okta.com/app".into()),
                role: Some("arn:aws:iam::123:role/R".into()),
                factor: None,
                duration: Some(3600),
            },
            secondary_role: Some(SecondaryRoleConfig {
                role_arn: "arn:aws:iam::456:role/S".into(),
            }),
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
