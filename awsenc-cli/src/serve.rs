use chrono::{TimeZone, Utc};

use awsenc_core::cache::{
    self, CacheFile, CacheHeader, FLAG_HAS_OKTA_SESSION, FORMAT_VERSION, MAGIC,
};
use awsenc_core::config::{self, ConfigOverrides};
use awsenc_core::credential::{AwsCredentials, CredentialProcessOutput, CredentialState};
use awsenc_core::okta::{OktaClient, OktaSession};
use awsenc_core::sts::{self, StsClient};
use enclaveapp_app_storage::EncryptionStorage;

use crate::cli::ServeArgs;
use crate::usage;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Handle the `credential_process` serve command.
///
/// Outputs JSON to stdout. Never prompts for input. Never prints anything to
/// stdout except the credential JSON.
#[allow(clippy::print_stderr)]
pub async fn run_serve(args: &ServeArgs, storage: &dyn EncryptionStorage) -> Result<()> {
    let profile = resolve_serve_profile(args)?;

    let Some(cache) = cache::read_cache(&profile)? else {
        eprintln!("No cached credentials for profile '{profile}'");
        eprintln!("Run: awsenc auth --profile {profile}");
        return Err("no cached credentials".into());
    };

    #[allow(clippy::cast_possible_wrap)]
    let exp_timestamp = cache.header.credential_expiration as i64;
    let chrono::LocalResult::Single(expiration) = Utc.timestamp_opt(exp_timestamp, 0) else {
        return Err("invalid credential expiration timestamp in cache".into());
    };

    let global = config::load_global_config().unwrap_or_default();
    #[allow(clippy::cast_possible_wrap)]
    let refresh_window = global.cache.refresh_window_seconds.unwrap_or(600) as i64;
    let state = CredentialState::from_expiration(expiration, refresh_window);

    match state {
        CredentialState::Fresh => {
            let creds = decrypt_aws_credentials(storage, &cache.aws_ciphertext)?;
            print_credentials(&creds)?;
            usage::record_usage(&profile);
        }
        CredentialState::Refresh => {
            match try_transparent_reauth(&profile, storage, &cache).await {
                Ok(new_creds) => {
                    print_credentials(&new_creds)?;
                }
                Err(e) => {
                    tracing::debug!("transparent re-auth failed: {e}; using cached credentials");
                    let creds = decrypt_aws_credentials(storage, &cache.aws_ciphertext)?;
                    print_credentials(&creds)?;
                }
            }
            usage::record_usage(&profile);
        }
        CredentialState::Expired => {
            let reauth_result = try_transparent_reauth(&profile, storage, &cache).await;
            if let Ok(new_creds) = reauth_result {
                print_credentials(&new_creds)?;
                usage::record_usage(&profile);
            } else {
                eprintln!("Credentials for profile '{profile}' are expired");
                eprintln!("Run: awsenc auth --profile {profile}");
                return Err("credentials expired".into());
            }
        }
    }

    Ok(())
}

pub(crate) fn resolve_serve_profile(args: &ServeArgs) -> Result<String> {
    if let Some(ref p) = args.profile {
        let global = config::load_global_config().unwrap_or_default();
        return Ok(config::resolve_alias(p, &global));
    }

    if args.active {
        if let Ok(p) = std::env::var("AWSENC_PROFILE") {
            if !p.is_empty() {
                let global = config::load_global_config().unwrap_or_default();
                return Ok(config::resolve_alias(&p, &global));
            }
        }
        return Err("--active specified but AWSENC_PROFILE is not set".into());
    }

    // Check AWSENC_PROFILE as fallback
    if let Ok(p) = std::env::var("AWSENC_PROFILE") {
        if !p.is_empty() {
            let global = config::load_global_config().unwrap_or_default();
            return Ok(config::resolve_alias(&p, &global));
        }
    }

    Err("no profile specified; use --profile <name> or --active".into())
}

fn decrypt_aws_credentials(
    storage: &dyn EncryptionStorage,
    ciphertext: &[u8],
) -> Result<AwsCredentials> {
    let plaintext = storage
        .decrypt(ciphertext)
        .map_err(|e| format!("failed to decrypt credentials: {e}"))?;
    let creds: AwsCredentials = serde_json::from_slice(&plaintext)?;
    Ok(creds)
}

#[allow(clippy::print_stdout)]
fn print_credentials(creds: &AwsCredentials) -> Result<()> {
    let output = CredentialProcessOutput::from_credentials(creds);
    // This is the ONLY thing that goes to stdout
    let json =
        serde_json::to_string(&output).map_err(|e| format!("credential JSON serialization failed: {e}"))?;
    println!("{json}");
    Ok(())
}

/// Attempt transparent re-authentication using a cached Okta session.
#[allow(clippy::cast_sign_loss)]
async fn try_transparent_reauth(
    profile: &str,
    storage: &dyn EncryptionStorage,
    cache: &CacheFile,
) -> Result<AwsCredentials> {
    let okta_ct = cache
        .okta_session_ciphertext
        .as_ref()
        .ok_or("no cached Okta session")?;

    #[allow(clippy::cast_possible_wrap)]
    let okta_exp_ts = cache.header.okta_session_expiration as i64;
    let chrono::LocalResult::Single(okta_exp) = Utc.timestamp_opt(okta_exp_ts, 0) else {
        return Err("invalid Okta session expiration".into());
    };

    if Utc::now() >= okta_exp {
        return Err("Okta session expired".into());
    }

    let okta_plaintext = storage
        .decrypt(okta_ct)
        .map_err(|e| format!("failed to decrypt Okta session: {e}"))?;
    let okta_session: OktaSession = serde_json::from_slice(&okta_plaintext)?;

    let global = config::load_global_config()?;
    let profile_config = config::load_profile_config(profile)?;
    let overrides = ConfigOverrides::from_env();
    let resolved = config::resolve_config(profile, &global, &profile_config, &overrides)?;
    if let Some(role) = resolved.secondary_role.as_deref() {
        return Err(format!(
            "secondary_role '{role}' is configured but chained role assumption is not supported yet"
        )
        .into());
    }

    let okta = OktaClient::new(&resolved.okta_organization)?;
    let saml_assertion = okta
        .get_saml_with_session(&okta_session.session_id, &resolved.okta_application)
        .await?;

    let roles = sts::parse_saml_roles(&saml_assertion)?;
    let matching_role = roles
        .iter()
        .find(|r| r.role_arn == resolved.okta_role)
        .ok_or("configured role not found in SAML assertion")?;

    let sts_client = StsClient::new();
    let creds = sts_client
        .assume_role_with_saml(
            &matching_role.role_arn,
            &matching_role.principal_arn,
            &saml_assertion,
            resolved.okta_duration,
        )
        .await?;

    let creds_json = serde_json::to_vec(&creds)?;
    let new_aws_ct = storage
        .encrypt(&creds_json)
        .map_err(|e| format!("failed to encrypt new credentials: {e}"))?;

    let new_cache = CacheFile {
        header: CacheHeader {
            magic: MAGIC,
            version: FORMAT_VERSION,
            flags: FLAG_HAS_OKTA_SESSION,
            credential_expiration: creds.expiration.timestamp() as u64,
            okta_session_expiration: okta_session.expiration.timestamp() as u64,
        },
        aws_ciphertext: new_aws_ct,
        okta_session_ciphertext: cache.okta_session_ciphertext.clone(),
    };

    cache::write_cache(profile, &new_cache)?;

    Ok(creds)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn resolve_serve_profile_explicit() {
        let args = ServeArgs {
            profile: Some("my-profile".to_string()),
            active: false,
        };
        let result = resolve_serve_profile(&args).unwrap();
        assert_eq!(result, "my-profile");
    }

    #[test]
    fn resolve_serve_profile_no_profile_no_active_no_env() {
        let prev = std::env::var("AWSENC_PROFILE").ok();
        std::env::remove_var("AWSENC_PROFILE");

        let args = ServeArgs {
            profile: None,
            active: false,
        };
        let result = resolve_serve_profile(&args);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("no profile specified"),
            "expected 'no profile specified', got: {err}"
        );

        if let Some(v) = prev {
            std::env::set_var("AWSENC_PROFILE", v);
        }
    }

    #[test]
    fn resolve_serve_profile_active_flag_without_env() {
        let prev = std::env::var("AWSENC_PROFILE").ok();
        std::env::remove_var("AWSENC_PROFILE");

        let args = ServeArgs {
            profile: None,
            active: true,
        };
        let result = resolve_serve_profile(&args);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("AWSENC_PROFILE is not set"),
            "expected AWSENC_PROFILE error, got: {err}"
        );

        if let Some(v) = prev {
            std::env::set_var("AWSENC_PROFILE", v);
        }
    }

    #[test]
    fn decrypt_aws_credentials_success() {
        use enclaveapp_app_storage::mock::MockEncryptionStorage as MockStorage;
        use zeroize::Zeroizing;

        let storage = MockStorage::new();
        let creds = AwsCredentials {
            access_key_id: "AKIAEXAMPLE".to_string(),
            secret_access_key: Zeroizing::new("secret".to_string()),
            session_token: Zeroizing::new("token".to_string()),
            expiration: Utc::now() + chrono::Duration::hours(1),
        };
        let json = serde_json::to_vec(&creds).unwrap();
        let ciphertext = storage.encrypt(&json).unwrap();

        let recovered = decrypt_aws_credentials(&storage, &ciphertext).unwrap();
        assert_eq!(recovered.access_key_id, "AKIAEXAMPLE");
    }

    #[test]
    fn decrypt_aws_credentials_bad_ciphertext() {
        use enclaveapp_app_storage::mock::MockEncryptionStorage as MockStorage;

        let storage = MockStorage::new();
        let result = decrypt_aws_credentials(&storage, &[0xFF; 50]);
        assert!(result.is_err());
    }

    #[test]
    fn output_credentials_produces_json() {
        use zeroize::Zeroizing;

        let creds = AwsCredentials {
            access_key_id: "AKIDTEST".to_string(),
            secret_access_key: Zeroizing::new("secret".to_string()),
            session_token: Zeroizing::new("token".to_string()),
            expiration: Utc::now(),
        };
        let json = serde_json::to_string(&CredentialProcessOutput::from_credentials(&creds)).unwrap();
        assert!(json.contains("AKIDTEST"));
        assert!(json.contains("Version"));
    }
}
