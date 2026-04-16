use std::io::IsTerminal;

use clap::{CommandFactory, Parser};
use clap_complete::generate;

use awsenc_core::cache;
use awsenc_core::config::{self, ConfigOverrides};
use awsenc_core::credential::CredentialState;
use awsenc_core::profile;
use enclaveapp_app_storage::{
    create_encryption_storage, AccessPolicy, EncryptionStorage, StorageConfig,
};

mod auth;
mod cli;
mod exec;
mod install;
mod picker;
mod serve;
mod shell_init;
mod usage;

use cli::{Cli, Commands};

#[cfg(test)]
pub(crate) static TEST_ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[tokio::main]
#[allow(clippy::print_stderr)]
async fn main() {
    let filter = tracing_subscriber::EnvFilter::try_from_env("AWSENC_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    if let Err(e) = dispatch(cli).await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

#[allow(clippy::print_stderr, clippy::print_stdout)]
async fn dispatch(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let force_keyring = cli.keyring;
    match cli.command {
        Commands::Auth(args) => {
            let profile = resolve_interactive_profile(args.resolved_profile())?;
            let global = config::load_global_config().unwrap_or_default();
            let profile = config::resolve_alias(&profile, &global);

            let biometric = resolve_biometric_for_profile(&profile, args.biometric);
            let storage = create_storage(biometric, force_keyring)?;

            auth::run_auth(&profile, &args, &*storage).await
        }

        Commands::Serve(args) => {
            let biometric = resolve_biometric_from_serve(&args);
            let storage = create_storage(biometric, force_keyring)?;
            serve::run_serve(&args, &*storage).await
        }

        Commands::Exec(args) => {
            let biometric = resolve_biometric_from_exec(&args);
            let storage = create_storage(biometric, force_keyring)?;
            exec::run_exec(&args, &*storage).await
        }

        Commands::Use(args) => {
            let profile = resolve_use_profile(args.profile.as_deref())?;
            let global = config::load_global_config().unwrap_or_default();
            let profile = config::resolve_alias(&profile, &global);

            if args.print_profile {
                println!("{profile}");
            } else {
                eprintln!("\nSwitched to profile: {profile}");
                eprintln!("Note: use 'awsenc-use' shell function to set env vars in your shell");
            }

            usage::record_usage(&profile);
            Ok(())
        }

        Commands::Install(args) => install::run_install(&args),
        Commands::Uninstall(args) => install::run_uninstall(&args),
        Commands::List(args) => run_list(&args),
        Commands::Clear(args) => run_clear(&args),
        Commands::ShellInit(args) => shell_init::run_shell_init(&args),
        Commands::Config => run_config(),

        Commands::Completions(args) => {
            let mut cmd = Cli::command();
            generate(args.shell, &mut cmd, "awsenc", &mut std::io::stdout());
            Ok(())
        }

        Commands::Migrate(args) => install::run_migrate(&args),
    }
}

fn resolve_interactive_profile(
    explicit: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(p) = explicit {
        return Ok(p.to_owned());
    }

    if let Ok(p) = std::env::var("AWSENC_PROFILE") {
        if !p.is_empty() {
            return Ok(p);
        }
    }

    if std::io::stdin().is_terminal() {
        let profiles = profile::list_profiles()?;
        let usage_data = usage::load_usage();
        let active = std::env::var("AWSENC_PROFILE").ok();
        return picker::pick_profile(&profiles, &usage_data, active.as_deref());
    }

    Err("no profile specified and stdin is not a TTY for interactive selection".into())
}

fn resolve_use_profile(explicit: Option<&str>) -> Result<String, Box<dyn std::error::Error>> {
    match explicit {
        Some(selector) => resolve_use_selector(selector),
        None => resolve_interactive_profile(None),
    }
}

fn resolve_use_selector(selector: &str) -> Result<String, Box<dyn std::error::Error>> {
    let Ok(rank) = selector.parse::<usize>() else {
        return Ok(selector.to_owned());
    };

    if rank == 0 {
        return Err("MRU rank must be 1 or greater".into());
    }

    let profiles = profile::list_profiles()?;
    let known_profiles: std::collections::HashSet<_> = profiles
        .iter()
        .map(|profile| profile.name.as_str())
        .collect();
    let usage_data = usage::load_usage();
    let mru_profiles: Vec<_> = usage::get_mru_profiles(&usage_data, profiles.len())
        .into_iter()
        .filter(|profile| known_profiles.contains(profile.as_str()))
        .collect();

    mru_profiles
        .get(rank - 1)
        .cloned()
        .ok_or_else(|| format!("MRU rank {rank} is out of range").into())
}

fn create_storage(
    biometric: bool,
    force_keyring: bool,
) -> Result<Box<dyn EncryptionStorage>, Box<dyn std::error::Error>> {
    let policy = if biometric {
        AccessPolicy::BiometricOnly
    } else {
        AccessPolicy::None
    };
    create_encryption_storage(StorageConfig {
        app_name: "awsenc".into(),
        key_label: "cache-key".into(),
        access_policy: policy,
        extra_bridge_paths: vec![],
        keys_dir: None,
        force_keyring,
    })
    .map_err(|e| format!("failed to initialize secure storage: {e}").into())
}

fn resolve_biometric_for_profile(profile: &str, cli_biometric: bool) -> bool {
    if cli_biometric {
        return true;
    }
    let global = config::load_global_config().unwrap_or_default();
    let Ok(profile_config) = config::load_profile_config(profile) else {
        return global.security.biometric.unwrap_or(false);
    };
    ConfigOverrides::from_env()
        .biometric
        .or(profile_config.security.biometric)
        .or(global.security.biometric)
        .unwrap_or(false)
}

fn resolve_biometric_from_serve(args: &cli::ServeArgs) -> bool {
    serve::resolve_serve_profile(args)
        .map(|profile| resolve_biometric_for_profile(&profile, false))
        .unwrap_or(false)
}

fn resolve_biometric_from_exec(args: &cli::ExecArgs) -> bool {
    exec::resolve_exec_profile(args)
        .map(|profile| resolve_biometric_for_profile(&profile, false))
        .unwrap_or(false)
}

#[allow(clippy::print_stderr, clippy::print_stdout)]
fn run_list(args: &cli::ListArgs) -> Result<(), Box<dyn std::error::Error>> {
    let profiles = profile::list_profiles()?;
    let usage_data = usage::load_usage();
    let active_profile = std::env::var("AWSENC_PROFILE").ok();

    if args.json {
        let output: Vec<serde_json::Value> = profiles
            .iter()
            .map(|p| {
                serde_json::json!({
                    "name": p.name,
                    "has_config": p.has_config,
                    "cache_state": p.cache_state.map(|s| s.to_string()),
                    "expiration": p.expiration.map(|e| e.to_rfc3339()),
                    "okta_session_expiration": p.okta_session_expiration.map(|e| e.to_rfc3339()),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }

    let mru = usage::get_mru_profiles(&usage_data, if args.all { 0 } else { 10 });
    let limit = if args.all { usize::MAX } else { 10 };

    let mut display: Vec<&profile::ProfileInfo> = Vec::new();

    for mru_name in &mru {
        if let Some(info) = profiles.iter().find(|p| &p.name == mru_name) {
            display.push(info);
        }
    }

    let remaining: Vec<&profile::ProfileInfo> =
        profiles.iter().filter(|p| !mru.contains(&p.name)).collect();
    display.extend(remaining);

    eprintln!("  {:<30} {:<20} Expires", "Profile", "Status");

    for info in display.iter().take(limit) {
        let active_marker = if active_profile.as_deref() == Some(&info.name) {
            "*"
        } else {
            " "
        };

        let status = match info.cache_state {
            Some(CredentialState::Fresh | CredentialState::Refresh) => "authenticated",
            Some(CredentialState::Expired) => "expired",
            None => "not cached",
        };

        let expires = format_expires(info.expiration);

        eprintln!(
            "  {:<28} {active_marker}  {:<20} {expires}",
            info.name, status
        );
    }

    let total = profiles.len();
    let shown = std::cmp::min(limit, display.len());
    if shown < total {
        eprintln!("\n  ... {} more, use --all to show", total - shown);
    }

    if active_profile.is_some() {
        eprintln!("\n  * = active profile");
    }

    Ok(())
}

fn format_expires(expiration: Option<chrono::DateTime<chrono::Utc>>) -> String {
    if let Some(exp) = expiration {
        let remaining = exp.signed_duration_since(chrono::Utc::now());
        let mins = remaining.num_minutes();
        if mins <= 0 {
            "--".to_owned()
        } else if mins >= 60 {
            format!("{}h {}m", mins / 60, mins % 60)
        } else {
            format!("{mins}m")
        }
    } else {
        "--".to_owned()
    }
}

#[allow(clippy::print_stderr)]
fn run_clear(args: &cli::ClearArgs) -> Result<(), Box<dyn std::error::Error>> {
    if args.all {
        if !args.force {
            eprintln!("This will clear ALL cached credentials.");
            eprint!("Continue? [y/N] ");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            if !input.trim().eq_ignore_ascii_case("y") {
                eprintln!("Cancelled");
                return Ok(());
            }
        }

        let profiles = profile::list_profiles()?;
        let mut cleared = 0;
        for p in &profiles {
            if cache::delete_cache(&p.name).is_ok() {
                cleared += 1;
            }
        }
        eprintln!("Cleared {cleared} cached credential(s)");
        return Ok(());
    }

    let profile = match args.resolved_profile() {
        Some(p) => {
            let global = config::load_global_config().unwrap_or_default();
            config::resolve_alias(p, &global)
        }
        None => resolve_interactive_profile(None)?,
    };

    if !args.force {
        eprint!("Clear cached credentials for '{profile}'? [y/N] ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            eprintln!("Cancelled");
            return Ok(());
        }
    }

    cache::delete_cache(&profile)?;
    eprintln!("Cleared cached credentials for '{profile}'");
    Ok(())
}

#[allow(clippy::print_stderr)]
fn run_config() -> Result<(), Box<dyn std::error::Error>> {
    let config_dir = config::config_dir()?;
    let profiles_dir = config::profiles_dir()?;
    let global_config_path = config_dir.join("config.toml");
    let usage_path = config_dir.join("usage.json");

    eprintln!("Configuration paths:");
    eprintln!("  Config directory:  {}", config_dir.display());
    eprintln!("  Global config:    {}", global_config_path.display());
    eprintln!("  Profiles dir:     {}", profiles_dir.display());
    eprintln!("  Usage data:       {}", usage_path.display());
    eprintln!();

    let global = config::load_global_config()?;
    eprintln!("Global settings:");
    eprintln!(
        "  Okta organization: {}",
        global.okta.organization.as_deref().unwrap_or("(not set)")
    );
    eprintln!(
        "  Okta user:         {}",
        global.okta.user.as_deref().unwrap_or("(not set)")
    );
    eprintln!(
        "  Default factor:    {}",
        global.okta.default_factor.as_deref().unwrap_or("push")
    );
    eprintln!(
        "  Biometric:         {}",
        global.security.biometric.unwrap_or(false)
    );
    eprintln!(
        "  Refresh window:    {}s",
        global.cache.refresh_window_seconds.unwrap_or(600)
    );

    let aliases = &global.aliases;
    if !aliases.is_empty() {
        eprintln!();
        eprintln!("Aliases:");
        for (alias, target) in aliases {
            eprintln!("  {alias} -> {target}");
        }
    }

    let profiles = profile::list_profiles()?;
    if !profiles.is_empty() {
        eprintln!();
        eprintln!("Profiles ({}):", profiles.len());
        for p in &profiles {
            eprintln!("  {}", p.name);
        }
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn format_expires_future_less_than_hour() {
        let exp = Some(chrono::Utc::now() + chrono::Duration::minutes(45));
        let result = format_expires(exp);
        assert!(
            result.contains("m"),
            "expected minutes notation, got: {result}"
        );
        assert!(!result.contains("h"), "should not contain hours: {result}");
    }

    #[test]
    fn format_expires_future_more_than_hour() {
        let exp =
            Some(chrono::Utc::now() + chrono::Duration::hours(2) + chrono::Duration::minutes(30));
        let result = format_expires(exp);
        assert!(
            result.contains("h"),
            "expected hours notation, got: {result}"
        );
        assert!(
            result.contains("m"),
            "expected minutes notation, got: {result}"
        );
    }

    #[test]
    fn format_expires_past() {
        let exp = Some(chrono::Utc::now() - chrono::Duration::minutes(10));
        let result = format_expires(exp);
        assert_eq!(result, "--");
    }

    #[test]
    fn format_expires_none() {
        let result = format_expires(None);
        assert_eq!(result, "--");
    }

    #[test]
    fn resolve_interactive_profile_explicit() {
        let result = resolve_interactive_profile(Some("myprofile")).unwrap();
        assert_eq!(result, "myprofile");
    }

    #[test]
    fn resolve_use_selector_returns_literal_profile_name() {
        let result = resolve_use_selector("myprofile").unwrap();
        assert_eq!(result, "myprofile");
    }

    #[test]
    fn resolve_use_selector_resolves_mru_rank() {
        use chrono::{Duration, Utc};
        use std::collections::HashMap;

        let _lock = TEST_ENV_MUTEX.lock().expect("mutex poisoned");
        let tmp = tempfile::tempdir().unwrap();
        let (prev_home, prev_userprofile, prev_xdg) = set_test_home(tmp.path());

        let prod = config::ProfileConfig {
            okta: config::ProfileOktaConfig {
                organization: Some("org.okta.com".into()),
                user: Some("prod@example.com".into()),
                application: Some("https://org.okta.com/app".into()),
                role: Some("arn:aws:iam::123:role/Prod".into()),
                factor: None,
                duration: None,
            },
            security: config::ProfileSecurityConfig::default(),
            region: None,
            secondary_role: None,
        };
        let dev = config::ProfileConfig {
            okta: config::ProfileOktaConfig {
                organization: Some("org.okta.com".into()),
                user: Some("dev@example.com".into()),
                application: Some("https://org.okta.com/app".into()),
                role: Some("arn:aws:iam::123:role/Dev".into()),
                factor: None,
                duration: None,
            },
            security: config::ProfileSecurityConfig::default(),
            region: None,
            secondary_role: None,
        };
        config::save_profile_config("prod-admin", &prod).unwrap();
        config::save_profile_config("dev-readonly", &dev).unwrap();

        let mut usage_data = usage::UsageData {
            profiles: HashMap::new(),
        };
        usage_data.profiles.insert(
            "prod-admin".into(),
            usage::ProfileUsage {
                last_used: Utc::now(),
                use_count: 3,
            },
        );
        usage_data.profiles.insert(
            "dev-readonly".into(),
            usage::ProfileUsage {
                last_used: Utc::now() - Duration::minutes(5),
                use_count: 1,
            },
        );
        usage::save_usage(&usage_data).unwrap();

        assert_eq!(resolve_use_selector("1").unwrap(), "prod-admin");
        assert_eq!(resolve_use_selector("2").unwrap(), "dev-readonly");

        restore_test_home(prev_home, prev_userprofile, prev_xdg);
    }

    #[test]
    fn resolve_use_selector_rejects_out_of_range_rank() {
        let _lock = TEST_ENV_MUTEX.lock().expect("mutex poisoned");
        let tmp = tempfile::tempdir().unwrap();
        let (prev_home, prev_userprofile, prev_xdg) = set_test_home(tmp.path());

        let err = resolve_use_selector("1").unwrap_err();
        assert!(err.to_string().contains("out of range"));

        restore_test_home(prev_home, prev_userprofile, prev_xdg);
    }

    #[test]
    fn resolve_biometric_for_nonexistent_profile() {
        let _lock = TEST_ENV_MUTEX.lock().expect("mutex poisoned");
        let tmp = tempfile::tempdir().unwrap();
        let (prev_home, prev_userprofile, prev_xdg) = set_test_home(tmp.path());
        let result = resolve_biometric_for_profile("nonexistent-profile-xyz", false);
        assert!(!result);
        restore_test_home(prev_home, prev_userprofile, prev_xdg);
    }

    #[test]
    fn resolve_biometric_for_profile_cli_override() {
        let _lock = TEST_ENV_MUTEX.lock().expect("mutex poisoned");
        let tmp = tempfile::tempdir().unwrap();
        let (prev_home, prev_userprofile, prev_xdg) = set_test_home(tmp.path());
        let result = resolve_biometric_for_profile("nonexistent-profile-xyz", true);
        assert!(result);
        restore_test_home(prev_home, prev_userprofile, prev_xdg);
    }

    #[test]
    fn resolve_biometric_from_serve_empty_profile() {
        let _lock = TEST_ENV_MUTEX.lock().expect("mutex poisoned");
        let tmp = tempfile::tempdir().unwrap();
        let (prev_home, prev_userprofile, prev_xdg) = set_test_home(tmp.path());
        let prev = std::env::var("AWSENC_PROFILE").ok();
        std::env::remove_var("AWSENC_PROFILE");

        let args = cli::ServeArgs {
            profile: None,
            active: false,
        };
        let result = resolve_biometric_from_serve(&args);
        assert!(!result);

        if let Some(v) = prev {
            std::env::set_var("AWSENC_PROFILE", v);
        }
        restore_test_home(prev_home, prev_userprofile, prev_xdg);
    }

    #[test]
    fn resolve_biometric_from_exec_empty_profile() {
        let _lock = TEST_ENV_MUTEX.lock().expect("mutex poisoned");
        let tmp = tempfile::tempdir().unwrap();
        let (prev_home, prev_userprofile, prev_xdg) = set_test_home(tmp.path());
        let prev = std::env::var("AWSENC_PROFILE").ok();
        std::env::remove_var("AWSENC_PROFILE");

        let args = cli::ExecArgs {
            profile_positional: None,
            profile_flag: None,
            command: vec!["echo".to_string()],
        };
        let result = resolve_biometric_from_exec(&args);
        assert!(!result);

        if let Some(v) = prev {
            std::env::set_var("AWSENC_PROFILE", v);
        }
        restore_test_home(prev_home, prev_userprofile, prev_xdg);
    }

    #[test]
    fn resolve_biometric_from_exec_with_profile() {
        let _lock = TEST_ENV_MUTEX.lock().expect("mutex poisoned");
        let tmp = tempfile::tempdir().unwrap();
        let (prev_home, prev_userprofile, prev_xdg) = set_test_home(tmp.path());

        let args = cli::ExecArgs {
            profile_positional: Some("some-profile".to_string()),
            profile_flag: None,
            command: vec!["echo".to_string()],
        };
        let result = resolve_biometric_from_exec(&args);
        assert!(!result);
        restore_test_home(prev_home, prev_userprofile, prev_xdg);
    }

    #[test]
    fn resolve_biometric_from_exec_uses_resolved_alias() {
        let _lock = TEST_ENV_MUTEX.lock().expect("mutex poisoned");
        let tmp = tempfile::tempdir().unwrap();
        let (prev_home, prev_userprofile, prev_xdg) = set_test_home(tmp.path());

        let mut global = config::GlobalConfig::default();
        global.okta.user = Some("tester@example.com".into());
        global.aliases.insert("prod".into(), "real-profile".into());
        let global_toml = toml::to_string_pretty(&global).unwrap();
        let config_dir = tmp.path().join(".config").join("awsenc");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(config_dir.join("config.toml"), global_toml).unwrap();

        let profile = config::ProfileConfig {
            okta: config::ProfileOktaConfig {
                organization: Some("org.okta.com".into()),
                user: None,
                application: Some("https://org.okta.com/app".into()),
                role: Some("arn:aws:iam::123:role/R".into()),
                factor: None,
                duration: None,
            },
            security: config::ProfileSecurityConfig::default(),
            region: None,
            secondary_role: None,
        };
        config::save_profile_config("real-profile", &profile).unwrap();

        let prev_bio = std::env::var("AWSENC_BIOMETRIC").ok();
        let prev_user = std::env::var("AWSENC_OKTA_USER").ok();
        std::env::set_var("AWSENC_BIOMETRIC", "true");
        std::env::set_var("AWSENC_OKTA_USER", "tester@example.com");
        let args = cli::ExecArgs {
            profile_positional: Some("prod".to_string()),
            profile_flag: None,
            command: vec!["echo".to_string()],
        };
        assert!(resolve_biometric_from_exec(&args));
        match prev_bio {
            Some(v) => std::env::set_var("AWSENC_BIOMETRIC", v),
            None => std::env::remove_var("AWSENC_BIOMETRIC"),
        }
        match prev_user {
            Some(v) => std::env::set_var("AWSENC_OKTA_USER", v),
            None => std::env::remove_var("AWSENC_OKTA_USER"),
        }
        restore_test_home(prev_home, prev_userprofile, prev_xdg);
    }

    fn set_test_home(path: &std::path::Path) -> (Option<String>, Option<String>, Option<String>) {
        let prev_home = std::env::var("HOME").ok();
        let prev_userprofile = std::env::var("USERPROFILE").ok();
        let prev_xdg = std::env::var("XDG_CONFIG_HOME").ok();
        std::env::set_var("HOME", path);
        std::env::set_var("USERPROFILE", path);
        std::env::set_var("XDG_CONFIG_HOME", path.join(".config"));
        (prev_home, prev_userprofile, prev_xdg)
    }

    fn restore_test_home(
        prev_home: Option<String>,
        prev_userprofile: Option<String>,
        prev_xdg: Option<String>,
    ) {
        match prev_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
        match prev_userprofile {
            Some(value) => std::env::set_var("USERPROFILE", value),
            None => std::env::remove_var("USERPROFILE"),
        }
        match prev_xdg {
            Some(value) => std::env::set_var("XDG_CONFIG_HOME", value),
            None => std::env::remove_var("XDG_CONFIG_HOME"),
        }
    }
}
