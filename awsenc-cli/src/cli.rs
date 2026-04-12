use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "awsenc", about = "Hardware-backed AWS credential manager")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
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
