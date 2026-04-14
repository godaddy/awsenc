use std::io::IsTerminal;
use std::process::Stdio;

use chrono::{TimeZone, Utc};

use awsenc_core::cache;
use awsenc_core::config::{self, ConfigOverrides};
use awsenc_core::credential::{AwsCredentials, CredentialState};
use awsenc_core::profile;
use enclaveapp_app_storage::EncryptionStorage;

use crate::cli::{AuthArgs, ExecArgs};
use crate::usage;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Run a child process with AWS credentials injected into its environment.
#[allow(clippy::exit, clippy::print_stderr)]
pub async fn run_exec(args: &ExecArgs, storage: &dyn EncryptionStorage) -> Result<()> {
    if args.command.is_empty() {
        return Err(
            "no command specified; usage: awsenc exec [PROFILE] -- <COMMAND> [ARGS...]".into(),
        );
    }

    let profile_name = resolve_exec_profile(args)?;
    let profile = profile_name.as_str();

    let cached = get_cached_credentials(profile, storage)?;
    let creds = if let Some(c) = cached {
        c
    } else {
        if !std::io::stdin().is_terminal() {
            return Err(
                "no cached credentials and stdin is not a TTY; run 'awsenc auth --pass-stdin' first"
                    .into(),
            );
        }
        eprintln!("No cached credentials for '{profile}', authenticating...");
        let auth_args = AuthArgs {
            profile_positional: Some(profile.to_owned()),
            profile_flag: None,
            user: None,
            organization: None,
            application: None,
            role: None,
            factor: None,
            duration: None,
            biometric: false,
            no_open: false,
            pass_stdin: false,
        };
        crate::auth::run_auth(profile, &auth_args, storage).await?;
        get_cached_credentials(profile, storage)?
            .ok_or("authentication succeeded but credentials not found in cache")?
    };

    let region = get_profile_region(profile);
    let cmd = &args.command[0];
    let cmd_args = &args.command[1..];

    let mut command = tokio::process::Command::new(cmd);
    command
        .args(cmd_args)
        .env("AWS_ACCESS_KEY_ID", &creds.access_key_id)
        .env("AWS_SECRET_ACCESS_KEY", creds.secret_access_key.as_str())
        .env("AWS_SESSION_TOKEN", creds.session_token.as_str())
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    if let Some(ref region) = region {
        command.env("AWS_DEFAULT_REGION", region);
    }

    let mut child = command
        .spawn()
        .map_err(|e| format!("failed to execute '{cmd}': {e}"))?;

    let status = child.wait().await?;
    usage::record_usage(profile);

    std::process::exit(status.code().unwrap_or(1));
}

pub(crate) fn resolve_exec_profile(args: &ExecArgs) -> Result<String> {
    if let Some(p) = args.resolved_profile() {
        let global = config::load_global_config().unwrap_or_default();
        return Ok(config::resolve_alias(p, &global));
    }

    if let Ok(p) = std::env::var("AWSENC_PROFILE") {
        if !p.is_empty() {
            let global = config::load_global_config().unwrap_or_default();
            return Ok(config::resolve_alias(&p, &global));
        }
    }

    if std::io::stdin().is_terminal() {
        let profiles = profile::list_profiles()?;
        let usage_data = usage::load_usage();
        let active = std::env::var("AWSENC_PROFILE").ok();
        let selected = crate::picker::pick_profile(&profiles, &usage_data, active.as_deref())?;
        let global = config::load_global_config().unwrap_or_default();
        return Ok(config::resolve_alias(&selected, &global));
    }

    Err("no profile specified; use --profile <name> or set AWSENC_PROFILE".into())
}

fn get_cached_credentials(
    profile: &str,
    storage: &dyn EncryptionStorage,
) -> Result<Option<AwsCredentials>> {
    let Some(cache) = cache::read_cache(profile)? else {
        return Ok(None);
    };

    #[allow(clippy::cast_possible_wrap)]
    let exp_ts = cache.header.credential_expiration as i64;
    let chrono::LocalResult::Single(expiration) = Utc.timestamp_opt(exp_ts, 0) else {
        return Ok(None);
    };

    // For exec, only reject if truly expired (no refresh window)
    let state = CredentialState::from_expiration(expiration, 0);
    if state == CredentialState::Expired {
        return Ok(None);
    }

    let plaintext = storage
        .decrypt(&cache.aws_ciphertext)
        .map_err(|e| format!("failed to decrypt credentials: {e}"))?;
    let creds: AwsCredentials = serde_json::from_slice(&plaintext)?;
    Ok(Some(creds))
}

fn get_profile_region(profile: &str) -> Option<String> {
    let global = config::load_global_config().ok()?;
    let profile_config = config::load_profile_config(profile).ok()?;
    let overrides = ConfigOverrides::from_env();
    let resolved = config::resolve_config(profile, &global, &profile_config, &overrides).ok()?;
    resolved.region
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use enclaveapp_app_storage::mock::MockEncryptionStorage as MockStorage;

    fn setup_temp_home(tmp: &tempfile::TempDir) -> Option<String> {
        let prev = std::env::var("HOME").ok();
        let config_dir = tmp.path().join(".config").join("awsenc");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::env::set_var("HOME", tmp.path());
        prev
    }

    fn restore_home(prev: Option<String>) {
        match prev {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn get_cached_credentials_returns_none_when_no_cache() {
        let _lock = crate::TEST_ENV_MUTEX.lock().expect("mutex poisoned");
        let tmp = tempfile::tempdir().unwrap();
        let prev = setup_temp_home(&tmp);
        let storage = MockStorage::new();
        let result = get_cached_credentials("nonexistent-profile-xyz", &storage).unwrap();
        assert!(result.is_none());
        restore_home(prev);
    }

    #[test]
    fn get_cached_credentials_returns_creds_when_fresh() {
        use awsenc_core::cache::{self, CacheFile, CacheHeader, FORMAT_VERSION, MAGIC};
        use zeroize::Zeroizing;

        let _lock = crate::TEST_ENV_MUTEX.lock().expect("mutex poisoned");
        let tmp = tempfile::tempdir().unwrap();
        let prev = setup_temp_home(&tmp);
        let storage = MockStorage::new();

        let creds = AwsCredentials {
            access_key_id: "AKIATEST".to_string(),
            secret_access_key: Zeroizing::new("secretkey".to_string()),
            session_token: Zeroizing::new("sessiontoken".to_string()),
            expiration: Utc::now() + chrono::Duration::hours(1),
        };
        let creds_json = serde_json::to_vec(&creds).unwrap();
        let ciphertext = storage.encrypt(&creds_json).unwrap();

        #[allow(clippy::cast_sign_loss)]
        let expiration_ts = creds.expiration.timestamp() as u64;
        let cache_file = CacheFile {
            header: CacheHeader {
                magic: MAGIC,
                version: FORMAT_VERSION,
                flags: 0,
                credential_expiration: expiration_ts,
                okta_session_expiration: 0,
            },
            aws_ciphertext: ciphertext,
            okta_session_ciphertext: None,
        };

        let profile = "test-cached-creds";
        cache::write_cache(profile, &cache_file).unwrap();

        let result = get_cached_credentials(profile, &storage).unwrap();
        assert!(result.is_some(), "should return cached credentials");
        let recovered = result.unwrap();
        assert_eq!(recovered.access_key_id, "AKIATEST");

        drop(cache::delete_cache(profile));
        restore_home(prev);
    }

    #[test]
    fn get_cached_credentials_returns_none_when_expired() {
        use awsenc_core::cache::{self, CacheFile, CacheHeader, FORMAT_VERSION, MAGIC};
        use zeroize::Zeroizing;

        let _lock = crate::TEST_ENV_MUTEX.lock().expect("mutex poisoned");
        let tmp = tempfile::tempdir().unwrap();
        let prev = setup_temp_home(&tmp);
        let storage = MockStorage::new();

        let creds = AwsCredentials {
            access_key_id: "AKIATEST".to_string(),
            secret_access_key: Zeroizing::new("secretkey".to_string()),
            session_token: Zeroizing::new("sessiontoken".to_string()),
            expiration: Utc::now() - chrono::Duration::hours(1),
        };
        let creds_json = serde_json::to_vec(&creds).unwrap();
        let ciphertext = storage.encrypt(&creds_json).unwrap();

        #[allow(clippy::cast_sign_loss)]
        let expiration_ts = creds.expiration.timestamp() as u64;
        let cache_file = CacheFile {
            header: CacheHeader {
                magic: MAGIC,
                version: FORMAT_VERSION,
                flags: 0,
                credential_expiration: expiration_ts,
                okta_session_expiration: 0,
            },
            aws_ciphertext: ciphertext,
            okta_session_ciphertext: None,
        };

        let profile = "test-expired-creds";
        cache::write_cache(profile, &cache_file).unwrap();

        let result = get_cached_credentials(profile, &storage).unwrap();
        assert!(
            result.is_none(),
            "should return None for expired credentials"
        );

        drop(cache::delete_cache(profile));
        restore_home(prev);
    }

    #[test]
    fn exec_args_resolved_profile_positional() {
        let args = ExecArgs {
            profile_positional: Some("my-profile".to_string()),
            profile_flag: None,
            command: vec!["echo".to_string()],
        };
        assert_eq!(args.resolved_profile(), Some("my-profile"));
    }

    #[test]
    fn exec_args_resolved_profile_flag() {
        let args = ExecArgs {
            profile_positional: None,
            profile_flag: Some("flag-profile".to_string()),
            command: vec!["echo".to_string()],
        };
        assert_eq!(args.resolved_profile(), Some("flag-profile"));
    }

    #[test]
    fn exec_args_resolved_profile_none() {
        let args = ExecArgs {
            profile_positional: None,
            profile_flag: None,
            command: vec!["echo".to_string()],
        };
        assert_eq!(args.resolved_profile(), None);
    }

    #[test]
    fn get_profile_region_returns_none_for_nonexistent() {
        let tmp = tempfile::tempdir().unwrap();
        std::env::set_var("HOME", tmp.path());
        assert!(get_profile_region("nonexistent-profile").is_none());
    }

    #[tokio::test]
    async fn run_exec_empty_command_returns_error() {
        let storage = MockStorage::new();
        let args = ExecArgs {
            profile_positional: Some("test".to_string()),
            profile_flag: None,
            command: vec![],
        };
        let result = run_exec(&args, &storage).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("no command"),
            "expected 'no command' error, got: {err}"
        );
    }

    #[tokio::test]
    async fn run_exec_without_cache_fails_fast_when_stdin_is_not_tty() {
        let storage = MockStorage::new();
        let args = ExecArgs {
            profile_positional: Some("test".to_string()),
            profile_flag: None,
            command: vec!["echo".to_string(), "hello".to_string()],
        };
        let result = run_exec(&args, &storage).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("stdin is not a TTY"));
    }
}
