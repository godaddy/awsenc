use crate::cli::ShellInitArgs;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Print the shell integration script to stdout.
#[allow(clippy::print_stdout)]
pub fn run_shell_init(args: &ShellInitArgs) -> Result<()> {
    let shell = detect_shell(args.shell.as_deref())?;

    match shell.as_str() {
        "bash" => print!("{}", bash_init()),
        "zsh" => print!("{}", zsh_init()),
        "fish" => print!("{}", fish_init()),
        "powershell" | "pwsh" => print!("{}", powershell_init()),
        other => return Err(format!("unsupported shell: {other}").into()),
    }

    Ok(())
}

fn detect_shell(explicit: Option<&str>) -> Result<String> {
    if let Some(s) = explicit {
        return Ok(s.to_lowercase());
    }

    if let Ok(shell) = std::env::var("SHELL") {
        if shell.contains("zsh") {
            return Ok("zsh".into());
        }
        if shell.contains("bash") {
            return Ok("bash".into());
        }
        if shell.contains("fish") {
            return Ok("fish".into());
        }
    }

    // Check PSModulePath for PowerShell
    if std::env::var("PSModulePath").is_ok() {
        return Ok("powershell".into());
    }

    Err("could not detect shell; specify one: bash, zsh, fish, powershell".into())
}

fn bash_init() -> &'static str {
    r#"# awsenc shell integration (bash)
# Add to ~/.bashrc: eval "$(awsenc shell-init bash)"

_awsenc_preexec() {
  local cmd="$BASH_COMMAND"
  if [[ "$cmd" =~ ^[[:space:]]*(export|declare\ -x)[[:space:]]+(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)= ]]; then
    echo "[awsenc] Warning: Exporting AWS credentials as environment variables defeats" >&2
    echo "hardware-backed protection. Use 'awsenc exec' or credential_process instead." >&2
  fi
}

# Install the DEBUG trap, chaining with any existing trap
if [[ -z "${_awsenc_trap_installed:-}" ]]; then
  _awsenc_existing_trap=$(trap -p DEBUG | sed "s/^trap -- '//;s/' DEBUG$//")
  if [[ -n "$_awsenc_existing_trap" ]]; then
    trap '_awsenc_preexec; eval "$_awsenc_existing_trap"' DEBUG
  else
    trap '_awsenc_preexec' DEBUG
  fi
  _awsenc_trap_installed=1
fi

# Shell function for 'awsenc use' (sets env vars in parent shell)
awsenc-use() {
  local profile
  profile=$(command awsenc use "$@" --print-profile) || return $?
  export AWSENC_PROFILE="$profile"
  export AWS_PROFILE="$profile"
  echo "Switched to profile: $profile" >&2
}
"#
}

fn zsh_init() -> &'static str {
    r#"# awsenc shell integration (zsh)
# Add to ~/.zshrc: eval "$(awsenc shell-init zsh)"

autoload -Uz add-zsh-hook

_awsenc_preexec() {
  local cmd="$1"
  if [[ "$cmd" =~ ^[[:space:]]*(export|declare\ -x)[[:space:]]+(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)= ]]; then
    echo "[awsenc] Warning: Exporting AWS credentials as environment variables defeats" >&2
    echo "hardware-backed protection. Use 'awsenc exec' or credential_process instead." >&2
  fi
}

add-zsh-hook preexec _awsenc_preexec

# Shell function for 'awsenc use' (sets env vars in parent shell)
awsenc-use() {
  local profile
  profile=$(command awsenc use "$@" --print-profile) || return $?
  export AWSENC_PROFILE="$profile"
  export AWS_PROFILE="$profile"
  echo "Switched to profile: $profile" >&2
}
"#
}

fn fish_init() -> &'static str {
    r#"# awsenc shell integration (fish)
# Add to ~/.config/fish/config.fish: awsenc shell-init fish | source

function __awsenc_check_export --on-event fish_preexec
    set -l cmd $argv[1]
    if string match -rq '^\s*set\s+(-gx|-Ux)\s+(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)\s' -- "$cmd"
        echo "[awsenc] Warning: Exporting AWS credentials as environment variables defeats" >&2
        echo "hardware-backed protection. Use 'awsenc exec' or credential_process instead." >&2
    end
end

function awsenc-use
    set -l profile (command awsenc use $argv --print-profile)
    or return $status
    set -gx AWSENC_PROFILE $profile
    set -gx AWS_PROFILE $profile
    echo "Switched to profile: $profile" >&2
end
"#
}

fn powershell_init() -> &'static str {
    r#"# awsenc shell integration (PowerShell)
# Add to $PROFILE: Invoke-Expression (awsenc shell-init powershell)

$_AwsEncOriginalPrompt = $function:prompt

function prompt {
    # Check recent history for AWS credential exports
    $lastCmd = (Get-History -Count 1).CommandLine 2>$null
    if ($lastCmd -match '\$env:(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)\s*=') {
        Write-Host "[awsenc] Warning: Setting AWS credentials as environment variables defeats" -ForegroundColor Yellow
        Write-Host "hardware-backed protection. Use 'awsenc exec' or credential_process instead." -ForegroundColor Yellow
    }
    & $_AwsEncOriginalPrompt
}

function awsenc-use {
    $profile = & awsenc use @args --print-profile
    if ($LASTEXITCODE -eq 0) {
        $env:AWSENC_PROFILE = $profile
        $env:AWS_PROFILE = $profile
        Write-Host "Switched to profile: $profile" -ForegroundColor Green
    }
}
"#
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn detect_shell_explicit() {
        assert_eq!(detect_shell(Some("bash")).unwrap(), "bash");
        assert_eq!(detect_shell(Some("ZSH")).unwrap(), "zsh");
        assert_eq!(detect_shell(Some("fish")).unwrap(), "fish");
        assert_eq!(detect_shell(Some("PowerShell")).unwrap(), "powershell");
    }

    #[test]
    fn bash_init_contains_function() {
        let script = bash_init();
        assert!(script.contains("awsenc-use()"));
        assert!(script.contains("_awsenc_preexec"));
        assert!(script.contains("AWSENC_PROFILE"));
    }

    #[test]
    fn zsh_init_contains_hook() {
        let script = zsh_init();
        assert!(script.contains("add-zsh-hook preexec"));
        assert!(script.contains("awsenc-use()"));
    }

    #[test]
    fn fish_init_contains_function() {
        let script = fish_init();
        assert!(script.contains("function awsenc-use"));
        assert!(script.contains("AWSENC_PROFILE"));
    }

    #[test]
    fn powershell_init_contains_function() {
        let script = powershell_init();
        assert!(script.contains("function awsenc-use"));
        assert!(script.contains("AWSENC_PROFILE"));
    }
}
