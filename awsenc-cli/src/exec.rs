use std::io::IsTerminal;
use std::process::Stdio;

use chrono::{TimeZone, Utc};

use awsenc_core::cache;
use awsenc_core::config::{self, ConfigOverrides};
use awsenc_core::credential::{AwsCredentials, CredentialState};
use awsenc_core::profile;
use awsenc_secure_storage::SecureStorage;

use crate::cli::{AuthArgs, ExecArgs};
use crate::usage;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Run a child process with AWS credentials injected into its environment.
pub async fn run_exec(args: &ExecArgs, storage: &dyn SecureStorage) -> Result<()> {
    if args.command.is_empty() {
        return Err(
            "no command specified; usage: awsenc exec [PROFILE] -- <COMMAND> [ARGS...]".into(),
        );
    }

    let profile_name = resolve_exec_profile(args)?;
    let profile = profile_name.as_str();

    let creds = if let Some(c) = get_cached_credentials(profile, storage)? {
        c
    } else {
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

fn resolve_exec_profile(args: &ExecArgs) -> Result<String> {
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
    storage: &dyn SecureStorage,
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
