use crate::cli::ShellInitArgs;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Print the shell integration script to stdout.
#[allow(clippy::print_stdout)]
pub fn run_shell_init(args: &ShellInitArgs) -> Result<()> {
    let shell = enclaveapp_wsl::shell_init::detect_shell(args.shell.as_deref())
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    let config = make_config();
    let script = enclaveapp_wsl::shell_init::generate_shell_init(&shell, &config)
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    print!("{script}");
    Ok(())
}

fn make_config() -> enclaveapp_wsl::shell_init::ShellInitConfig {
    enclaveapp_wsl::shell_init::ShellInitConfig {
        command: "awsenc".to_string(),
        export_patterns: vec![
            "AWS_ACCESS_KEY_ID".to_string(),
            "AWS_SECRET_ACCESS_KEY".to_string(),
            "AWS_SESSION_TOKEN".to_string(),
        ],
        export_warning: vec![
            "[awsenc] Warning: Exporting AWS credentials as environment variables defeats"
                .to_string(),
            "hardware-backed protection. Use 'awsenc exec' or credential_process instead."
                .to_string(),
        ],
        include_powershell: true,
        helper_function: Some(enclaveapp_wsl::shell_init::ShellHelperFunction {
            name: "awsenc-use".to_string(),
            bash_body: r#"  local profile
  profile=$(command awsenc use "$@" --print-profile) || return $?
  export AWSENC_PROFILE="$profile"
  export AWS_PROFILE="$profile"
  echo "Switched to profile: $profile" >&2"#
                .to_string(),
            fish_body: r#"    set -l profile (command awsenc use $argv --print-profile)
    or return $status
    set -gx AWSENC_PROFILE $profile
    set -gx AWS_PROFILE $profile
    echo "Switched to profile: $profile" >&2"#
                .to_string(),
            powershell_body: r#"    $profile = & awsenc use @args --print-profile
    if ($LASTEXITCODE -eq 0) {
        $env:AWSENC_PROFILE = $profile
        $env:AWS_PROFILE = $profile
        Write-Host "Switched to profile: $profile" -ForegroundColor Green
    }"#
            .to_string(),
        }),
        command_wrapper: false,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn detect_shell_explicit() {
        assert_eq!(
            enclaveapp_wsl::shell_init::detect_shell(Some("bash")).unwrap(),
            "bash"
        );
        assert_eq!(
            enclaveapp_wsl::shell_init::detect_shell(Some("ZSH")).unwrap(),
            "zsh"
        );
        assert_eq!(
            enclaveapp_wsl::shell_init::detect_shell(Some("fish")).unwrap(),
            "fish"
        );
        assert_eq!(
            enclaveapp_wsl::shell_init::detect_shell(Some("PowerShell")).unwrap(),
            "powershell"
        );
    }

    #[test]
    fn bash_init_contains_function() {
        let config = make_config();
        let script = enclaveapp_wsl::shell_init::generate_shell_init("bash", &config).unwrap();
        assert!(script.contains("awsenc-use()"));
        assert!(script.contains("_awsenc_preexec"));
        assert!(script.contains("AWSENC_PROFILE"));
    }

    #[test]
    fn zsh_init_contains_hook() {
        let config = make_config();
        let script = enclaveapp_wsl::shell_init::generate_shell_init("zsh", &config).unwrap();
        assert!(script.contains("add-zsh-hook preexec"));
        assert!(script.contains("awsenc-use()"));
    }

    #[test]
    fn fish_init_contains_function() {
        let config = make_config();
        let script = enclaveapp_wsl::shell_init::generate_shell_init("fish", &config).unwrap();
        assert!(script.contains("function awsenc-use"));
        assert!(script.contains("AWSENC_PROFILE"));
    }

    #[test]
    fn powershell_init_contains_function() {
        let config = make_config();
        let script =
            enclaveapp_wsl::shell_init::generate_shell_init("powershell", &config).unwrap();
        assert!(script.contains("function awsenc-use"));
        assert!(script.contains("AWSENC_PROFILE"));
    }
}
