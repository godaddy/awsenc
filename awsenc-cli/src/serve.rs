use chrono::{TimeZone, Utc};

use awsenc_core::cache::{self};
use awsenc_core::config;
use awsenc_core::credential::{AwsCredentials, CredentialProcessOutput, CredentialState};
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
        CredentialState::Fresh | CredentialState::Refresh => {
            let creds = decrypt_aws_credentials(storage, &cache.aws_ciphertext)?;
            output_credentials(&creds)?;
            usage::record_usage(&profile);
        }
        CredentialState::Expired => {
            eprintln!("Credentials for profile '{profile}' are expired");
            eprintln!("Run: awsenc auth --profile {profile}");
            return Err("credentials expired".into());
        }
    }

    Ok(())
}

fn resolve_serve_profile(args: &ServeArgs) -> Result<String> {
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
fn output_credentials(creds: &AwsCredentials) -> Result<()> {
    let output = CredentialProcessOutput::from_credentials(creds);
    // This is the ONLY thing that goes to stdout
    let json = serde_json::to_string(&output)?;
    println!("{json}");
    Ok(())
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
        let _lock = crate::test_support::ENV_MUTEX
            .lock()
            .expect("mutex poisoned");
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
        let _lock = crate::test_support::ENV_MUTEX
            .lock()
            .expect("mutex poisoned");
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
        let output = CredentialProcessOutput::from_credentials(&creds);
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("AKIDTEST"));
        assert!(json.contains("Version"));
    }
}
