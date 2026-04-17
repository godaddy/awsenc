use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};

use chrono::{TimeZone, Utc};
use fs4::fs_std::FileExt;

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
///
/// Concurrent `awsenc serve` invocations for the same profile are serialized
/// with an exclusive advisory file lock on `<profile>.enc.lock`. Two parallel
/// AWS CLI calls that both see the cache as Refresh/Expired would otherwise
/// each fire the STS / transparent-reauth chain; the lock collapses them so
/// only one does the work and the second reads the refreshed cache.
#[allow(clippy::print_stderr)]
pub async fn run_serve(args: &ServeArgs, storage: &dyn EncryptionStorage) -> Result<()> {
    let profile = resolve_serve_profile(args)?;

    let lock_path = serve_lock_path(&profile)?;
    let _guard = ServeLock::acquire(&lock_path)?;

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
            let creds = decrypt_aws_credentials_with_envelope(
                &profile,
                storage,
                &cache.header,
                &cache.aws_ciphertext,
            )?;
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
                    let creds = decrypt_aws_credentials_with_envelope(
                        &profile,
                        storage,
                        &cache.header,
                        &cache.aws_ciphertext,
                    )?;
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

/// Lock file path: sibling of the cache file, named `<profile>.enc.lock`.
fn serve_lock_path(profile: &str) -> Result<PathBuf> {
    let mut path = cache::cache_path(profile)?;
    let mut name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".lock");
    path.set_file_name(name);
    Ok(path)
}

/// Exclusive file lock held for the duration of a single serve invocation.
/// The lock file itself is empty; its only job is to advisory-lock the inode.
struct ServeLock {
    file: fs::File,
}

impl ServeLock {
    fn acquire(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("creating lock directory {}: {e}", parent.display()))?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(|e| format!("opening lock file {}: {e}", path.display()))?;
        FileExt::lock_exclusive(&file)
            .map_err(|e| format!("acquiring exclusive lock on {}: {e}", path.display()))?;
        Ok(Self { file })
    }
}

impl Drop for ServeLock {
    fn drop(&mut self) {
        drop(FileExt::unlock(&self.file));
    }
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

#[cfg(test)]
fn decrypt_aws_credentials(
    storage: &dyn EncryptionStorage,
    ciphertext: &[u8],
) -> Result<AwsCredentials> {
    // Legacy path: no header-binding or anti-rollback check. Used by
    // unit tests that construct ciphertexts without the envelope.
    let plaintext = storage
        .decrypt(ciphertext)
        .map_err(|e| format!("failed to decrypt credentials: {e}"))?;
    let creds: AwsCredentials = serde_json::from_slice(&plaintext)?;
    Ok(creds)
}

fn decrypt_aws_credentials_with_envelope(
    profile: &str,
    storage: &dyn EncryptionStorage,
    header: &CacheHeader,
    ciphertext: &[u8],
) -> Result<AwsCredentials> {
    let plaintext = storage
        .decrypt(ciphertext)
        .map_err(|e| format!("failed to decrypt credentials: {e}"))?;
    let min_counter = cache::read_counter(profile).unwrap_or(0);
    let (_counter, payload) = cache::unwrap_after_decrypt(header, min_counter, &plaintext)?;
    let creds: AwsCredentials = serde_json::from_slice(&payload)?;
    Ok(creds)
}

#[allow(clippy::print_stdout)]
fn print_credentials(creds: &AwsCredentials) -> Result<()> {
    let output = CredentialProcessOutput::from_credentials(creds);
    // This is the ONLY thing that goes to stdout
    let json = serde_json::to_string(&output)
        .map_err(|e| format!("credential JSON serialization failed: {e}"))?;
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
    let min_counter = cache::read_counter(profile).unwrap_or(0);
    let (observed_counter, okta_payload) =
        cache::unwrap_after_decrypt(&cache.header, min_counter, &okta_plaintext)?;
    let okta_session: OktaSession = serde_json::from_slice(&okta_payload)?;

    let global = config::load_global_config()?;
    let profile_config = config::load_profile_config(profile)?;
    let overrides = ConfigOverrides::from_env();
    let resolved = config::resolve_config(profile, &global, &profile_config, &overrides)?;

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

    // Build the refreshed cache's new header first so we can bind its
    // bytes into the re-encrypted credential envelope.
    let new_header = CacheHeader {
        magic: MAGIC,
        version: FORMAT_VERSION,
        flags: FLAG_HAS_OKTA_SESSION,
        credential_expiration: creds.expiration.timestamp() as u64,
        okta_session_expiration: okta_session.expiration.timestamp() as u64,
    };

    // Bump the monotonic rollback counter. `prior_observed` comes
    // from the ciphertext we just successfully decrypted above — if
    // an attacker deleted the sidecar to reset it to 0, the counter
    // still can't go backwards, because we started from whatever was
    // embedded in the last good cache.
    let prior_sidecar = cache::read_counter(profile).unwrap_or(0);
    let counter = cache::next_counter(prior_sidecar, observed_counter);

    let creds_json = serde_json::to_vec(&creds)?;
    let aws_wrapped = cache::wrap_for_encrypt(&new_header, counter, &creds_json);
    let new_aws_ct = storage
        .encrypt(&aws_wrapped)
        .map_err(|e| format!("failed to encrypt new credentials: {e}"))?;

    // Re-wrap the okta session under the new header so its envelope
    // stays consistent with the refreshed header hash.
    let okta_json = serde_json::to_vec(&okta_session)?;
    let okta_wrapped = cache::wrap_for_encrypt(&new_header, counter, &okta_json);
    let new_okta_ct = storage
        .encrypt(&okta_wrapped)
        .map_err(|e| format!("failed to re-encrypt Okta session: {e}"))?;

    let new_cache = CacheFile {
        header: new_header,
        aws_ciphertext: new_aws_ct,
        okta_session_ciphertext: Some(new_okta_ct),
    };

    cache::write_cache(profile, &new_cache)?;
    if let Err(e) = cache::write_counter(profile, counter) {
        tracing::warn!("failed to persist rollback-counter sidecar for profile '{profile}': {e}");
    }

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
        let _lock = crate::TEST_ENV_MUTEX.lock().expect("mutex poisoned");
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
        let _lock = crate::TEST_ENV_MUTEX.lock().expect("mutex poisoned");
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
        let json =
            serde_json::to_string(&CredentialProcessOutput::from_credentials(&creds)).unwrap();
        assert!(json.contains("AKIDTEST"));
        assert!(json.contains("Version"));
    }
}
