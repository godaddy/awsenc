use std::io::{IsTerminal, Write};
use std::path::PathBuf;

use enclaveapp_core::config_block::{self, BlockMarkers};
use enclaveapp_core::metadata;
use enclaveapp_core::quoting;
use regex::Regex;

use awsenc_core::cache;
use awsenc_core::config::{self, ProfileConfig, ProfileOktaConfig, ProfileSecurityConfig};
use awsenc_core::profile;

use crate::cli::{InstallArgs, MigrateArgs, UninstallArgs};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Install a profile: create config file and add managed block to ~/.aws/config.
#[allow(clippy::print_stderr)]
pub fn run_install(args: &InstallArgs) -> Result<()> {
    if args.wizard && !std::io::stdin().is_terminal() {
        return Err("--wizard requires an interactive terminal".into());
    }

    let profile_name = match args.resolved_profile() {
        Some(p) => p.to_owned(),
        None => {
            if std::io::stdin().is_terminal() {
                prompt_profile_name()?
            } else {
                return Err("no profile name specified".into());
            }
        }
    };
    let profile_name = config::validate_profile_name(&profile_name)?.to_owned();

    let user = if args.wizard {
        prompt_optional("Okta username", args.user.as_deref())?
    } else {
        args.user.clone()
    };
    let organization = if args.wizard {
        Some(prompt_required(
            "Okta organization FQDN",
            args.organization.as_deref(),
        )?)
    } else {
        args.organization.clone()
    };
    let application = if args.wizard {
        Some(prompt_required(
            "Okta application URL",
            args.application.as_deref(),
        )?)
    } else {
        args.application.clone()
    };
    let role = if args.wizard {
        Some(prompt_required("AWS role ARN", args.role.as_deref())?)
    } else {
        args.role.clone()
    };
    let factor = if args.wizard {
        prompt_optional("Default MFA factor", args.factor.as_deref())?
    } else {
        args.factor.clone()
    };
    let duration = if args.wizard {
        prompt_optional_u64("STS session duration (seconds)", args.duration)?
    } else {
        args.duration
    };
    let region = if args.wizard {
        prompt_optional("AWS region", args.region.as_deref())?
    } else {
        args.region.clone()
    };
    let biometric = if args.wizard && !args.biometric {
        prompt_bool("Require biometric for decrypt", false)?
    } else {
        args.biometric
    };

    // Build profile config from args
    let profile_config = ProfileConfig {
        okta: ProfileOktaConfig {
            organization,
            user,
            application,
            role,
            factor,
            duration,
        },
        security: ProfileSecurityConfig {
            biometric: Some(biometric),
        },
        region,
    };

    // Save profile config
    config::save_profile_config(&profile_name, &profile_config)?;
    eprintln!(
        "Saved profile config: {}",
        profile_config_path(&profile_name)?.display()
    );

    // Find the awsenc binary path
    let binary_path = std::env::current_exe()?;
    let binary_path_str = binary_path
        .to_str()
        .ok_or("binary path contains non-UTF-8 characters")?;

    // Update ~/.aws/config
    let aws_config_path = aws_config_path()?;
    let existing = if aws_config_path.exists() {
        std::fs::read_to_string(&aws_config_path)?
    } else {
        // Create the directory if needed
        if let Some(parent) = aws_config_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        String::new()
    };

    let managed_block = build_managed_block(
        &profile_name,
        binary_path_str,
        profile_config.region.as_deref(),
    )?;

    let updated = upsert_managed_block(&existing, &profile_name, &managed_block);
    write_text_file(&aws_config_path, &updated)?;

    eprintln!("Updated {}", aws_config_path.display());
    eprintln!("Installed profile '{profile_name}'");
    eprintln!("Authenticate with: awsenc auth --profile {profile_name}");

    Ok(())
}

/// Uninstall a profile: remove managed block from ~/.aws/config and delete config/cache.
#[allow(clippy::print_stderr)]
pub fn run_uninstall(args: &UninstallArgs) -> Result<()> {
    let profile_name = args
        .profile
        .as_deref()
        .ok_or("no profile specified; use --profile <name>")?;
    let profile_name = config::validate_profile_name(profile_name)?;

    // Remove managed block from ~/.aws/config
    let aws_config_path = aws_config_path()?;
    if aws_config_path.exists() {
        let existing = std::fs::read_to_string(&aws_config_path)?;
        let updated = remove_managed_block(&existing, profile_name);
        write_text_file(&aws_config_path, &updated)?;
        eprintln!("Removed managed block from {}", aws_config_path.display());
    }

    // Delete profile config
    let config_path = profile_config_path(profile_name)?;
    if config_path.exists() {
        std::fs::remove_file(&config_path)?;
        eprintln!("Removed {}", config_path.display());
    }

    // Delete cache
    drop(cache::delete_cache(profile_name));
    eprintln!("Uninstalled profile '{profile_name}'");

    Ok(())
}

/// Migrate from aws-okta-processor configuration.
#[allow(clippy::print_stderr)]
pub fn run_migrate(args: &MigrateArgs) -> Result<()> {
    let aws_config_path = aws_config_path()?;
    let aws_creds_path = aws_credentials_path()?;

    let mut sources = Vec::new();

    if aws_config_path.exists() {
        let content = std::fs::read_to_string(&aws_config_path)?;
        sources.push(("~/.aws/config".to_owned(), content));
    }

    if aws_creds_path.exists() {
        let content = std::fs::read_to_string(&aws_creds_path)?;
        sources.push(("~/.aws/credentials".to_owned(), content));
    }

    if sources.is_empty() {
        eprintln!("No AWS config files found");
        return Ok(());
    }

    let binary_path = std::env::current_exe()?;
    let binary_path_str = binary_path
        .to_str()
        .ok_or("binary path contains non-UTF-8 characters")?;

    let mut migrated_profiles = Vec::new();

    for (source_name, content) in &sources {
        let entries = find_okta_processor_entries(content);
        if entries.is_empty() {
            eprintln!("No aws-okta-processor entries found in {source_name}");
            continue;
        }

        for entry in &entries {
            eprintln!("Found profile '{}' in {source_name}", entry.profile_name);

            if args.dry_run {
                eprintln!("  [dry-run] Would create profile config:");
                eprintln!("    organization: {:?}", entry.organization);
                eprintln!("    user: {:?}", entry.user);
                eprintln!("    application: {:?}", entry.application);
                eprintln!("    role: {:?}", entry.role);
                eprintln!("    factor: {:?}", entry.factor);
                eprintln!("    duration: {:?}", entry.duration);
                if entry.secondary_role.is_some() {
                    eprintln!("    secondary_role: unsupported; profile would be skipped");
                }
                continue;
            }

            // Check if profile already exists
            if profile::profile_exists(&entry.profile_name) && !args.force {
                eprintln!(
                    "  Skipping '{}' (already exists; use --force to overwrite)",
                    entry.profile_name
                );
                continue;
            }

            if entry.secondary_role.is_some() {
                eprintln!(
                    "  Skipping '{}' (secondary-role chaining is not supported yet)",
                    entry.profile_name
                );
                continue;
            }

            // Create profile config
            let profile_config = ProfileConfig {
                okta: ProfileOktaConfig {
                    organization: entry.organization.clone(),
                    user: entry.user.clone(),
                    application: entry.application.clone(),
                    role: entry.role.clone(),
                    factor: entry.factor.clone(),
                    duration: entry.duration,
                },
                security: ProfileSecurityConfig::default(),
                region: entry.region.clone(),
            };

            config::save_profile_config(&entry.profile_name, &profile_config)?;
            migrated_profiles.push(entry.profile_name.clone());
            eprintln!("  Created profile config for '{}'", entry.profile_name);
        }
    }

    if args.dry_run {
        eprintln!("\nDry run complete; no files were modified");
        return Ok(());
    }

    // Update ~/.aws/config with new credential_process lines
    if !migrated_profiles.is_empty() {
        let aws_config = if aws_config_path.exists() {
            std::fs::read_to_string(&aws_config_path)?
        } else {
            String::new()
        };

        let mut updated = comment_out_okta_processor_entries(&aws_config);
        for profile_name in &migrated_profiles {
            let block = build_managed_block(profile_name, binary_path_str, None)?;
            updated = upsert_managed_block(&updated, profile_name, &block);
        }

        write_text_file(&aws_config_path, &updated)?;
        eprintln!("\nMigrated {} profile(s)", migrated_profiles.len());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn aws_config_path() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or("could not determine home directory")?;
    Ok(home.join(".aws").join("config"))
}

fn aws_credentials_path() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or("could not determine home directory")?;
    Ok(home.join(".aws").join("credentials"))
}

fn profile_config_path(name: &str) -> Result<PathBuf> {
    Ok(config::profile_config_path(name)?)
}

fn prompt_profile_name() -> Result<String> {
    loop {
        let value = prompt_required("Profile name", None)?;
        match config::validate_profile_name(&value) {
            Ok(validated) => return Ok(validated.to_owned()),
            Err(err) => write_stderr_line(&format!("Invalid profile name: {err}"))?,
        }
    }
}

fn prompt_required(label: &str, current: Option<&str>) -> Result<String> {
    loop {
        let value = prompt_line(label, current)?;
        if !value.is_empty() {
            return Ok(value);
        }
        write_stderr_line(&format!("{label} is required"))?;
    }
}

fn prompt_optional(label: &str, current: Option<&str>) -> Result<Option<String>> {
    let value = prompt_line(label, current)?;
    if value.is_empty() {
        Ok(None)
    } else {
        Ok(Some(value))
    }
}

fn prompt_optional_u64(label: &str, current: Option<u64>) -> Result<Option<u64>> {
    loop {
        let current_str = current.map(|value| value.to_string());
        let value = prompt_line(label, current_str.as_deref())?;
        if value.is_empty() {
            return Ok(None);
        }
        match value.parse::<u64>() {
            Ok(parsed) => return Ok(Some(parsed)),
            Err(_) => write_stderr_line(&format!("{label} must be an unsigned integer"))?,
        }
    }
}

fn prompt_bool(label: &str, default: bool) -> Result<bool> {
    loop {
        let suffix = if default { "[Y/n]" } else { "[y/N]" };
        write_stderr(&format!("{label} {suffix}: "))?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Ok(default);
        }
        match trimmed.to_ascii_lowercase().as_str() {
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => write_stderr_line("Please answer yes or no")?,
        }
    }
}

fn prompt_line(label: &str, current: Option<&str>) -> Result<String> {
    match current {
        Some(existing) if !existing.is_empty() => write_stderr(&format!("{label} [{existing}]: "))?,
        _ => write_stderr(&format!("{label}: "))?,
    }

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let trimmed = input.trim();
    if trimmed.is_empty() {
        Ok(current.unwrap_or_default().to_owned())
    } else {
        Ok(trimmed.to_owned())
    }
}

fn write_stderr(message: &str) -> Result<()> {
    let mut stderr = std::io::stderr();
    stderr.write_all(message.as_bytes())?;
    stderr.flush()?;
    Ok(())
}

fn write_stderr_line(message: &str) -> Result<()> {
    write_stderr(message)?;
    write_stderr("\n")
}

fn build_managed_block(
    profile_name: &str,
    binary_path: &str,
    region: Option<&str>,
) -> Result<String> {
    use std::fmt::Write;

    let profile_name = config::validate_profile_name(profile_name)?;
    let quoted_path = quoting::quote_config_value(binary_path);
    let mut body = format!(
        "[profile {profile_name}]\n\
         credential_process = {quoted_path} serve --profile {profile_name}\n"
    );
    if let Some(r) = region {
        let _ = writeln!(body, "region = {r}");
    }
    let markers = BlockMarkers::with_id("awsenc", profile_name);
    Ok(config_block::build_block(&markers, &body))
}

fn upsert_managed_block(existing: &str, profile_name: &str, new_block: &str) -> String {
    let markers = BlockMarkers::with_id("awsenc", profile_name);
    config_block::upsert_block(existing, &markers, new_block)
}

fn remove_managed_block(existing: &str, profile_name: &str) -> String {
    let markers = BlockMarkers::with_id("awsenc", profile_name);
    let (result, _status) = config_block::remove_block(existing, &markers);
    result
}

fn comment_out_okta_processor_entries(existing: &str) -> String {
    let mut result = String::with_capacity(existing.len());
    for line in existing.lines() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with('#')
            && !trimmed.starts_with(';')
            && trimmed.starts_with("credential_process")
            && (trimmed.contains("aws-okta-processor") || trimmed.contains("aws_okta_processor"))
        {
            result.push_str("# ");
            result.push_str(line);
        } else {
            result.push_str(line);
        }
        result.push('\n');
    }
    result
}

fn write_text_file(path: &std::path::Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    metadata::atomic_write(path, contents.as_bytes())
        .map_err(|e| format!("failed to write {}: {e}", path.display()).into())
}

/// Parsed aws-okta-processor entry from an AWS config file.
struct OktaProcessorEntry {
    profile_name: String,
    organization: Option<String>,
    user: Option<String>,
    application: Option<String>,
    role: Option<String>,
    factor: Option<String>,
    duration: Option<u64>,
    region: Option<String>,
    secondary_role: Option<String>,
}

/// Find `aws-okta-processor` `credential_process` entries in an AWS config file.
fn find_okta_processor_entries(content: &str) -> Vec<OktaProcessorEntry> {
    let mut entries = Vec::new();
    let mut current_profile: Option<String> = None;
    let mut current_cred_process: Option<String> = None;
    let mut current_region: Option<String> = None;

    let profile_re = Regex::new(r"^\[(?:profile\s+)?([^\]]+)\]").expect("valid regex");

    for line in content.lines() {
        let trimmed = line.trim();

        if let Some(caps) = profile_re.captures(trimmed) {
            // Flush previous profile
            if let (Some(name), Some(cp)) = (current_profile.take(), current_cred_process.take()) {
                if cp.contains("aws-okta-processor") || cp.contains("aws_okta_processor") {
                    entries.push(parse_okta_processor_line(&name, &cp, current_region.take()));
                }
            }
            current_profile = Some(caps[1].to_owned());
            current_cred_process = None;
            current_region = None;
        } else if trimmed.starts_with("credential_process") {
            if let Some(value) = trimmed.split_once('=').map(|(_, v)| v.trim()) {
                current_cred_process = Some(value.to_owned());
            }
        } else if trimmed.starts_with("region") {
            current_region = trimmed.split_once('=').map(|(_, v)| v.trim().to_owned());
        }
    }

    // Flush last profile
    if let (Some(name), Some(cp)) = (current_profile, current_cred_process) {
        if cp.contains("aws-okta-processor") || cp.contains("aws_okta_processor") {
            entries.push(parse_okta_processor_line(&name, &cp, current_region));
        }
    }

    entries
}

fn parse_okta_processor_line(
    profile_name: &str,
    command_line: &str,
    region: Option<String>,
) -> OktaProcessorEntry {
    fn extract_flag(line: &str, flag: &str) -> Option<String> {
        let patterns = [format!("--{flag} "), format!("--{flag}=")];
        for pat in &patterns {
            if let Some(pos) = line.find(pat.as_str()) {
                let start = pos + pat.len();
                let rest = &line[start..];
                let value = if let Some(stripped) = rest.strip_prefix('"') {
                    stripped.split('"').next()
                } else if let Some(stripped) = rest.strip_prefix('\'') {
                    stripped.split('\'').next()
                } else {
                    rest.split_whitespace().next()
                };
                return value.map(str::to_owned);
            }
        }
        None
    }

    OktaProcessorEntry {
        profile_name: profile_name.to_owned(),
        organization: extract_flag(command_line, "organization"),
        user: extract_flag(command_line, "user"),
        application: extract_flag(command_line, "application"),
        role: extract_flag(command_line, "role"),
        factor: extract_flag(command_line, "factor"),
        duration: extract_flag(command_line, "duration").and_then(|d| d.parse().ok()),
        region,
        secondary_role: extract_flag(command_line, "secondary-role"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_managed_block_no_region() {
        let block =
            build_managed_block("prod", "/usr/local/bin/awsenc", None).expect("managed block");
        assert!(block.contains("[profile prod]"));
        assert!(block.contains("credential_process = /usr/local/bin/awsenc serve --profile prod"));
        assert!(block.contains("BEGIN awsenc managed (prod)"));
        assert!(block.contains("END awsenc managed (prod)"));
        assert!(!block.contains("region"));
    }

    #[test]
    fn build_managed_block_with_region() {
        let block = build_managed_block("prod", "/usr/local/bin/awsenc", Some("us-west-2"))
            .expect("managed block");
        assert!(block.contains("region = us-west-2"));
    }

    #[test]
    fn build_managed_block_quotes_binary_with_spaces() {
        let block = build_managed_block("prod", "/Applications/Aws Enc/awsenc", None)
            .expect("managed block");
        assert!(block.contains(
            "credential_process = \"/Applications/Aws Enc/awsenc\" serve --profile prod"
        ));
    }

    #[test]
    fn upsert_managed_block_append() {
        let existing = "[profile other]\nsome = value\n";
        let block = build_managed_block("new", "/bin/awsenc", None).expect("managed block");
        let result = upsert_managed_block(existing, "new", &block);
        assert!(result.contains("[profile other]"));
        assert!(result.contains("[profile new]"));
    }

    #[test]
    fn upsert_managed_block_replace() {
        let block1 = build_managed_block("prod", "/old/path", None).expect("managed block");
        let existing = format!("before\n{block1}\nafter\n");
        let block2 =
            build_managed_block("prod", "/new/path", Some("us-east-1")).expect("managed block");
        let result = upsert_managed_block(&existing, "prod", &block2);
        assert!(result.contains("/new/path"));
        assert!(!result.contains("/old/path"));
        assert!(result.contains("before"));
        assert!(result.contains("after"));
    }

    #[test]
    fn remove_managed_block_present() {
        let block = build_managed_block("test", "/bin/awsenc", None).expect("managed block");
        let existing = format!("header\n\n{block}\n\nfooter\n");
        let result = remove_managed_block(&existing, "test");
        assert!(!result.contains("awsenc managed"));
        assert!(result.contains("header"));
        assert!(result.contains("footer"));
    }

    #[test]
    fn remove_managed_block_absent() {
        let existing = "[profile something]\nkey = val\n";
        let result = remove_managed_block(existing, "nonexistent");
        assert_eq!(result, existing);
    }

    #[test]
    fn find_okta_processor_entries_basic() {
        let content = r"
[profile myaccount]
credential_process = aws-okta-processor authenticate --organization mycompany.okta.com --application https://mycompany.okta.com/home/amazon_aws/0oa123/272 --role arn:aws:iam::123456789012:role/MyRole --factor push --duration 3600
region = us-west-2
";
        let entries = find_okta_processor_entries(content);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].profile_name, "myaccount");
        assert_eq!(
            entries[0].organization.as_deref(),
            Some("mycompany.okta.com")
        );
        assert_eq!(entries[0].factor.as_deref(), Some("push"));
        assert_eq!(entries[0].duration, Some(3600));
        assert_eq!(entries[0].region.as_deref(), Some("us-west-2"));
    }

    #[test]
    fn find_okta_processor_entries_none() {
        let content = "[profile something]\nkey = value\n";
        let entries = find_okta_processor_entries(content);
        assert!(entries.is_empty());
    }

    #[test]
    fn upsert_managed_block_empty_existing() {
        let block = build_managed_block("test", "/bin/awsenc", None).expect("managed block");
        let result = upsert_managed_block("", "test", &block);
        assert!(result.contains("[profile test]"));
    }

    #[test]
    fn parse_okta_processor_line_extracts_user() {
        let entry = parse_okta_processor_line(
            "prod",
            "aws-okta-processor authenticate --user jane@example.com --organization mycompany.okta.com",
            None,
        );
        assert_eq!(entry.user.as_deref(), Some("jane@example.com"));
    }

    #[test]
    fn comment_out_okta_processor_entries_comments_live_lines() {
        let input = "[profile prod]\ncredential_process = aws-okta-processor authenticate --organization test.okta.com\nregion = us-west-2\n";
        let result = comment_out_okta_processor_entries(input);
        assert!(result.contains(
            "# credential_process = aws-okta-processor authenticate --organization test.okta.com"
        ));
        assert!(result.contains("region = us-west-2"));
    }

    #[test]
    fn find_okta_processor_entries_multiple() {
        let content = r"
[profile account1]
credential_process = aws-okta-processor authenticate --organization org1.okta.com --application https://org1.okta.com/app1 --role arn:aws:iam::111:role/Role1 --factor push
region = us-east-1

[profile account2]
credential_process = aws-okta-processor authenticate --organization org2.okta.com --application https://org2.okta.com/app2 --role arn:aws:iam::222:role/Role2 --factor totp --duration 7200
";
        let entries = find_okta_processor_entries(content);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].profile_name, "account1");
        assert_eq!(entries[0].organization.as_deref(), Some("org1.okta.com"));
        assert_eq!(entries[0].factor.as_deref(), Some("push"));
        assert!(entries[0].duration.is_none());
        assert_eq!(entries[0].region.as_deref(), Some("us-east-1"));

        assert_eq!(entries[1].profile_name, "account2");
        assert_eq!(entries[1].organization.as_deref(), Some("org2.okta.com"));
        assert_eq!(entries[1].factor.as_deref(), Some("totp"));
        assert_eq!(entries[1].duration, Some(7200));
        assert!(entries[1].region.is_none());
    }

    #[test]
    fn find_okta_processor_entries_with_secondary_role() {
        let content = r"
[profile withsecondary]
credential_process = aws-okta-processor authenticate --organization org.okta.com --application https://org.okta.com/app --role arn:aws:iam::123:role/Primary --secondary-role arn:aws:iam::456:role/Secondary
";
        let entries = find_okta_processor_entries(content);
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].secondary_role.as_deref(),
            Some("arn:aws:iam::456:role/Secondary")
        );
    }

    #[test]
    fn find_okta_processor_entries_non_profile_section() {
        let content = r"
[account1]
credential_process = aws-okta-processor authenticate --organization org.okta.com
";
        let entries = find_okta_processor_entries(content);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].profile_name, "account1");
    }

    #[test]
    fn find_okta_processor_entries_underscore_variant() {
        let content = r"
[profile test]
credential_process = aws_okta_processor authenticate --organization org.okta.com
";
        let entries = find_okta_processor_entries(content);
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn find_okta_processor_entries_quoted_values() {
        let content = r#"
[profile quoted]
credential_process = aws-okta-processor authenticate --organization "my org.okta.com" --application "https://example.com/app"
"#;
        let entries = find_okta_processor_entries(content);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].organization.as_deref(), Some("my org.okta.com"));
    }

    #[test]
    fn remove_managed_block_only_block() {
        let block = build_managed_block("only", "/bin/awsenc", None).expect("managed block");
        let existing = format!("{block}\n");
        let result = remove_managed_block(&existing, "only");
        // Should be empty or just whitespace
        assert!(
            !result.contains("awsenc managed"),
            "managed block should be removed"
        );
    }

    #[test]
    fn upsert_managed_block_no_trailing_newline() {
        let existing = "[profile other]\nkey = value";
        let block = build_managed_block("new", "/bin/awsenc", None).expect("managed block");
        let result = upsert_managed_block(existing, "new", &block);
        assert!(result.contains("[profile other]"));
        assert!(result.contains("[profile new]"));
    }

    #[test]
    fn parse_okta_processor_line_equals_format() {
        let entry = parse_okta_processor_line(
            "test",
            "aws-okta-processor authenticate --organization=org.okta.com --factor=push",
            Some("us-west-1".into()),
        );
        assert_eq!(entry.organization.as_deref(), Some("org.okta.com"));
        assert_eq!(entry.factor.as_deref(), Some("push"));
        assert_eq!(entry.region.as_deref(), Some("us-west-1"));
    }
}
