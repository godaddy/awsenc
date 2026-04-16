use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "awsenc",
    version,
    about = "Hardware-backed AWS credential manager"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Force the system keyring backend (Linux only). Bypasses WSL bridge
    /// and TPM detection. Requires an unlocked keyring session.
    #[arg(long, global = true)]
    pub keyring: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Authenticate with Okta and cache AWS credentials
    Auth(AuthArgs),
    /// Output credentials as JSON (for `credential_process`)
    Serve(ServeArgs),
    /// Run a command with AWS credentials injected
    Exec(ExecArgs),
    /// Set the active profile (with interactive picker)
    Use(UseArgs),
    /// Configure AWS CLI profiles to use awsenc
    Install(InstallArgs),
    /// Remove awsenc configuration from AWS CLI profiles
    Uninstall(UninstallArgs),
    /// List configured profiles and cache status
    List(ListArgs),
    /// Clear cached credentials for a profile (or all)
    Clear(ClearArgs),
    /// Print shell integration script (export detection)
    ShellInit(ShellInitArgs),
    /// Show configuration paths and current settings
    Config,
    /// Generate shell completions
    Completions(CompletionsArgs),
    /// Migrate from `aws-okta-processor` configuration
    Migrate(MigrateArgs),
}

#[derive(Parser)]
pub struct AuthArgs {
    /// Profile name or alias (omit for interactive picker)
    pub profile_positional: Option<String>,

    /// Profile name (alternative to positional arg)
    #[arg(short, long = "profile")]
    pub profile_flag: Option<String>,

    /// Okta username (overrides config)
    #[arg(short, long)]
    pub user: Option<String>,

    /// Okta organization FQDN (overrides config)
    #[arg(short, long)]
    pub organization: Option<String>,

    /// Okta application URL (overrides config)
    #[arg(short, long)]
    pub application: Option<String>,

    /// AWS role ARN (overrides config)
    #[arg(short, long)]
    pub role: Option<String>,

    /// MFA factor type: push, totp, yubikey (overrides config)
    #[arg(short, long)]
    pub factor: Option<String>,

    /// STS session duration in seconds (default: 3600)
    #[arg(short, long)]
    pub duration: Option<u64>,

    /// Require biometric for this session's cache
    #[arg(long)]
    pub biometric: bool,

    /// Don't auto-open browser for `WebAuthn`
    #[arg(long)]
    pub no_open: bool,

    /// Read password from stdin instead of prompting
    #[arg(long)]
    pub pass_stdin: bool,
}

impl AuthArgs {
    pub fn resolved_profile(&self) -> Option<&str> {
        self.profile_positional
            .as_deref()
            .or(self.profile_flag.as_deref())
    }
}

#[derive(Parser)]
pub struct ServeArgs {
    /// Profile name
    #[arg(short, long)]
    pub profile: Option<String>,

    /// Use `AWSENC_PROFILE` env var
    #[arg(long)]
    pub active: bool,
}

#[derive(Parser)]
pub struct ExecArgs {
    /// Profile name or alias (before --)
    pub profile_positional: Option<String>,

    /// Profile name (alternative to positional arg)
    #[arg(short, long = "profile")]
    pub profile_flag: Option<String>,

    /// Command and arguments to execute (after --)
    #[arg(last = true, required = true)]
    pub command: Vec<String>,
}

impl ExecArgs {
    pub fn resolved_profile(&self) -> Option<&str> {
        self.profile_positional
            .as_deref()
            .or(self.profile_flag.as_deref())
    }
}

#[derive(Parser)]
pub struct UseArgs {
    /// Profile name, alias, or MRU rank number
    pub profile: Option<String>,

    /// Print the resolved profile name to stdout and exit
    #[arg(long)]
    pub print_profile: bool,
}

#[derive(Parser)]
pub struct InstallArgs {
    /// Profile name
    pub profile_positional: Option<String>,

    /// Profile name (alternative to positional arg)
    #[arg(short, long = "profile")]
    pub profile_flag: Option<String>,

    /// Okta username
    #[arg(short, long)]
    pub user: Option<String>,

    /// Okta organization FQDN
    #[arg(short, long)]
    pub organization: Option<String>,

    /// Okta application URL
    #[arg(short, long)]
    pub application: Option<String>,

    /// AWS role ARN
    #[arg(short, long)]
    pub role: Option<String>,

    /// Default MFA factor
    #[arg(short, long)]
    pub factor: Option<String>,

    /// Default STS session duration in seconds
    #[arg(short, long)]
    pub duration: Option<u64>,

    /// AWS region for this profile
    #[arg(long)]
    pub region: Option<String>,

    /// Require biometric for decryption
    #[arg(long)]
    pub biometric: bool,

    /// Run an interactive setup wizard for missing values
    #[arg(long)]
    pub wizard: bool,
}

impl InstallArgs {
    pub fn resolved_profile(&self) -> Option<&str> {
        self.profile_positional
            .as_deref()
            .or(self.profile_flag.as_deref())
    }
}

#[derive(Parser)]
pub struct UninstallArgs {
    /// Profile name
    #[arg(short, long)]
    pub profile: Option<String>,
}

#[derive(Parser)]
pub struct ListArgs {
    /// Output as JSON
    #[arg(long)]
    pub json: bool,

    /// Show all profiles (default: MRU order, top 10)
    #[arg(long)]
    pub all: bool,
}

#[derive(Parser)]
pub struct ClearArgs {
    /// Profile name or alias (omit for interactive picker)
    pub profile_positional: Option<String>,

    /// Profile name
    #[arg(short, long = "profile")]
    pub profile_flag: Option<String>,

    /// Clear all cached credentials
    #[arg(long)]
    pub all: bool,

    /// Skip confirmation prompt
    #[arg(long)]
    pub force: bool,
}

impl ClearArgs {
    pub fn resolved_profile(&self) -> Option<&str> {
        self.profile_positional
            .as_deref()
            .or(self.profile_flag.as_deref())
    }
}

#[derive(Parser)]
pub struct ShellInitArgs {
    /// Shell type: bash, zsh, fish, powershell (auto-detected if omitted)
    pub shell: Option<String>,
}

#[derive(Parser)]
pub struct CompletionsArgs {
    /// Shell to generate completions for
    pub shell: clap_complete::Shell,
}

#[derive(Parser)]
pub struct MigrateArgs {
    /// Show what would change without modifying files
    #[arg(long)]
    pub dry_run: bool,

    /// Overwrite existing awsenc profiles
    #[arg(long)]
    pub force: bool,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parse_auth_with_profile() {
        let cli = Cli::parse_from(["awsenc", "auth", "my-profile"]);
        match cli.command {
            Commands::Auth(args) => {
                assert_eq!(args.profile_positional.as_deref(), Some("my-profile"));
            }
            _ => panic!("expected Auth command"),
        }
    }

    #[test]
    fn parse_auth_with_all_flags() {
        let cli = Cli::parse_from([
            "awsenc",
            "auth",
            "--profile",
            "prof",
            "--user",
            "user@example.com",
            "--organization",
            "org.okta.com",
            "--application",
            "https://org.okta.com/app",
            "--role",
            "arn:aws:iam::123:role/R",
            "--factor",
            "push",
            "--duration",
            "7200",
            "--biometric",
            "--no-open",
            "--pass-stdin",
        ]);
        match cli.command {
            Commands::Auth(args) => {
                assert_eq!(args.profile_flag.as_deref(), Some("prof"));
                assert_eq!(args.user.as_deref(), Some("user@example.com"));
                assert_eq!(args.organization.as_deref(), Some("org.okta.com"));
                assert!(args.biometric);
                assert!(args.no_open);
                assert!(args.pass_stdin);
                assert_eq!(args.duration, Some(7200));
            }
            _ => panic!("expected Auth command"),
        }
    }

    #[test]
    fn parse_serve_with_profile() {
        let cli = Cli::parse_from(["awsenc", "serve", "--profile", "prod"]);
        match cli.command {
            Commands::Serve(args) => {
                assert_eq!(args.profile.as_deref(), Some("prod"));
                assert!(!args.active);
            }
            _ => panic!("expected Serve command"),
        }
    }

    #[test]
    fn parse_serve_active() {
        let cli = Cli::parse_from(["awsenc", "serve", "--active"]);
        match cli.command {
            Commands::Serve(args) => {
                assert!(args.active);
                assert!(args.profile.is_none());
            }
            _ => panic!("expected Serve command"),
        }
    }

    #[test]
    fn parse_exec_with_command() {
        let cli = Cli::parse_from(["awsenc", "exec", "--", "aws", "s3", "ls"]);
        match cli.command {
            Commands::Exec(args) => {
                assert_eq!(args.command, vec!["aws", "s3", "ls"]);
                assert!(args.profile_positional.is_none());
            }
            _ => panic!("expected Exec command"),
        }
    }

    #[test]
    fn parse_exec_with_profile_and_command() {
        let cli = Cli::parse_from(["awsenc", "exec", "prod", "--", "aws", "s3", "ls"]);
        match cli.command {
            Commands::Exec(args) => {
                assert_eq!(args.profile_positional.as_deref(), Some("prod"));
                assert_eq!(args.command, vec!["aws", "s3", "ls"]);
            }
            _ => panic!("expected Exec command"),
        }
    }

    #[test]
    fn parse_install_with_all_flags() {
        let cli = Cli::parse_from([
            "awsenc",
            "install",
            "myprofile",
            "--user",
            "u",
            "--organization",
            "o",
            "--application",
            "a",
            "--role",
            "r",
            "--factor",
            "push",
            "--duration",
            "3600",
            "--region",
            "us-west-2",
            "--biometric",
        ]);
        match cli.command {
            Commands::Install(args) => {
                assert_eq!(args.resolved_profile(), Some("myprofile"));
                assert_eq!(args.user.as_deref(), Some("u"));
                assert_eq!(args.region.as_deref(), Some("us-west-2"));
                assert!(args.biometric);
                assert!(!args.wizard);
            }
            _ => panic!("expected Install command"),
        }
    }

    #[test]
    fn parse_list_json() {
        let cli = Cli::parse_from(["awsenc", "list", "--json"]);
        match cli.command {
            Commands::List(args) => {
                assert!(args.json);
                assert!(!args.all);
            }
            _ => panic!("expected List command"),
        }
    }

    #[test]
    fn parse_clear_all_force() {
        let cli = Cli::parse_from(["awsenc", "clear", "--all", "--force"]);
        match cli.command {
            Commands::Clear(args) => {
                assert!(args.all);
                assert!(args.force);
            }
            _ => panic!("expected Clear command"),
        }
    }

    #[test]
    fn parse_clear_with_profile() {
        let cli = Cli::parse_from(["awsenc", "clear", "my-profile"]);
        match cli.command {
            Commands::Clear(args) => {
                assert_eq!(args.resolved_profile(), Some("my-profile"));
            }
            _ => panic!("expected Clear command"),
        }
    }

    #[test]
    fn parse_use_with_print_profile() {
        let cli = Cli::parse_from(["awsenc", "use", "prod", "--print-profile"]);
        match cli.command {
            Commands::Use(args) => {
                assert_eq!(args.profile.as_deref(), Some("prod"));
                assert!(args.print_profile);
            }
            _ => panic!("expected Use command"),
        }
    }

    #[test]
    fn parse_shell_init_with_shell() {
        let cli = Cli::parse_from(["awsenc", "shell-init", "zsh"]);
        match cli.command {
            Commands::ShellInit(args) => {
                assert_eq!(args.shell.as_deref(), Some("zsh"));
            }
            _ => panic!("expected ShellInit command"),
        }
    }

    #[test]
    fn parse_migrate_dry_run() {
        let cli = Cli::parse_from(["awsenc", "migrate", "--dry-run"]);
        match cli.command {
            Commands::Migrate(args) => {
                assert!(args.dry_run);
                assert!(!args.force);
            }
            _ => panic!("expected Migrate command"),
        }
    }

    #[test]
    fn parse_config_command() {
        let cli = Cli::parse_from(["awsenc", "config"]);
        assert!(matches!(cli.command, Commands::Config));
    }

    #[test]
    fn parse_completions_bash() {
        let cli = Cli::parse_from(["awsenc", "completions", "bash"]);
        match cli.command {
            Commands::Completions(args) => {
                assert_eq!(args.shell, clap_complete::Shell::Bash);
            }
            _ => panic!("expected Completions command"),
        }
    }

    #[test]
    fn auth_args_resolved_profile_positional_priority() {
        let args = AuthArgs {
            profile_positional: Some("pos".to_string()),
            profile_flag: Some("flag".to_string()),
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
        assert_eq!(args.resolved_profile(), Some("pos"));
    }

    #[test]
    fn install_args_resolved_profile_flag() {
        let args = InstallArgs {
            profile_positional: None,
            profile_flag: Some("flagged".to_string()),
            user: None,
            organization: None,
            application: None,
            role: None,
            factor: None,
            duration: None,
            region: None,
            biometric: false,
            wizard: false,
        };
        assert_eq!(args.resolved_profile(), Some("flagged"));
    }

    #[test]
    fn clear_args_resolved_profile_positional() {
        let args = ClearArgs {
            profile_positional: Some("pos".to_string()),
            profile_flag: Some("flag".to_string()),
            all: false,
            force: false,
        };
        assert_eq!(args.resolved_profile(), Some("pos"));
    }

    #[test]
    fn exec_args_resolved_profile_flag_priority() {
        let args = ExecArgs {
            profile_positional: None,
            profile_flag: Some("flagged".to_string()),
            command: vec!["echo".to_string()],
        };
        assert_eq!(args.resolved_profile(), Some("flagged"));
    }
}
