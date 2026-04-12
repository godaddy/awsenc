use std::io::IsTerminal;
use std::path::PathBuf;

use regex::Regex;

use awsenc_core::cache;
use awsenc_core::config::{self, ProfileConfig, ProfileOktaConfig, SecondaryRoleConfig};
use awsenc_core::profile;

use crate::cli::{InstallArgs, MigrateArgs, UninstallArgs};
use crate::usage;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Install a profile: create config file and add managed block to ~/.aws/config.
#[allow(clippy::print_stderr)]
pub fn run_install(args: &InstallArgs) -> Result<()> {
    let profile_name = match args.resolved_profile() {
        Some(p) => p.to_owned(),
        None => {
            if std::io::stdin().is_terminal() {
                let profiles = profile::list_profiles()?;
                let usage_data = usage::load_usage();
                let active = std::env::var("AWSENC_PROFILE").ok();
                crate::picker::pick_profile(&profiles, &usage_data, active.as_deref())?
            } else {
                return Err("no profile name specified".into());
            }
        }
    };

    // Build profile config from args
    let profile_config = ProfileConfig {
        okta: ProfileOktaConfig {
            organization: args.organization.clone(),
            application: args.application.clone(),
            role: args.role.clone(),
            factor: args.factor.clone(),
            duration: args.duration,
        },
        secondary_role: None,
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

    let managed_block = build_managed_block(&profile_name, binary_path_str, args.region.as_deref());

    let updated = upsert_managed_block(&existing, &profile_name, &managed_block);
    std::fs::write(&aws_config_path, &updated)?;

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

    // Remove managed block from ~/.aws/config
    let aws_config_path = aws_config_path()?;
    if aws_config_path.exists() {
        let existing = std::fs::read_to_string(&aws_config_path)?;
        let updated = remove_managed_block(&existing, profile_name);
        std::fs::write(&aws_config_path, &updated)?;
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
                eprintln!("    application: {:?}", entry.application);
                eprintln!("    role: {:?}", entry.role);
                eprintln!("    factor: {:?}", entry.factor);
                eprintln!("    duration: {:?}", entry.duration);
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

            // Create profile config
            let profile_config = ProfileConfig {
                okta: ProfileOktaConfig {
                    organization: entry.organization.clone(),
                    application: entry.application.clone(),
                    role: entry.role.clone(),
                    factor: entry.factor.clone(),
                    duration: entry.duration,
                },
                secondary_role: entry.secondary_role.as_ref().map(|r| SecondaryRoleConfig {
                    role_arn: r.clone(),
                }),
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

        let mut updated = aws_config;
        for profile_name in &migrated_profiles {
            let block = build_managed_block(profile_name, binary_path_str, None);
            updated = upsert_managed_block(&updated, profile_name, &block);
        }

        std::fs::write(&aws_config_path, &updated)?;
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
    let dir = config::profiles_dir()?;
    Ok(dir.join(format!("{name}.toml")))
}

fn build_managed_block(profile_name: &str, binary_path: &str, region: Option<&str>) -> String {
    use std::fmt::Write;

    let mut block = format!(
        "# --- BEGIN awsenc managed ({profile_name}) ---\n\
         [profile {profile_name}]\n\
         credential_process = {binary_path} serve --profile {profile_name}\n"
    );
    if let Some(r) = region {
        let _ = writeln!(block, "region = {r}");
    }
    let _ = write!(block, "# --- END awsenc managed ({profile_name}) ---");
    block
}

fn upsert_managed_block(existing: &str, profile_name: &str, new_block: &str) -> String {
    let begin = format!("# --- BEGIN awsenc managed ({profile_name}) ---");
    let end = format!("# --- END awsenc managed ({profile_name}) ---");

    if let (Some(start), Some(end_pos)) = (existing.find(&begin), existing.find(&end)) {
        let before = &existing[..start];
        let after = &existing[end_pos + end.len()..];
        format!("{before}{new_block}{after}")
    } else {
        // Append
        let mut result = existing.to_owned();
        if !result.is_empty() && !result.ends_with('\n') {
            result.push('\n');
        }
        if !result.is_empty() {
            result.push('\n');
        }
        result.push_str(new_block);
        result.push('\n');
        result
    }
}

fn remove_managed_block(existing: &str, profile_name: &str) -> String {
    let begin = format!("# --- BEGIN awsenc managed ({profile_name}) ---");
    let end = format!("# --- END awsenc managed ({profile_name}) ---");

    if let (Some(start), Some(end_pos)) = (existing.find(&begin), existing.find(&end)) {
        let before = &existing[..start];
        let after = &existing[end_pos + end.len()..];
        // Clean up double newlines
        let after = after.trim_start_matches('\n');
        let mut result = before.to_owned();
        if !result.is_empty() && result.ends_with('\n') && !after.is_empty() {
            // Keep one newline separator
        } else if !result.is_empty() && !result.ends_with('\n') && !after.is_empty() {
            result.push('\n');
        }
        result.push_str(after);
        result
    } else {
        existing.to_owned()
    }
}

/// Parsed aws-okta-processor entry from an AWS config file.
struct OktaProcessorEntry {
    profile_name: String,
    organization: Option<String>,
    application: Option<String>,
    role: Option<String>,
    factor: Option<String>,
    duration: Option<u64>,
    secondary_role: Option<String>,
}

/// Find `aws-okta-processor` `credential_process` entries in an AWS config file.
fn find_okta_processor_entries(content: &str) -> Vec<OktaProcessorEntry> {
    let mut entries = Vec::new();
    let mut current_profile: Option<String> = None;
    let mut current_cred_process: Option<String> = None;

    let profile_re = Regex::new(r"^\[(?:profile\s+)?([^\]]+)\]").expect("valid regex");

    for line in content.lines() {
        let trimmed = line.trim();

        if let Some(caps) = profile_re.captures(trimmed) {
            // Flush previous profile
            if let (Some(name), Some(cp)) = (current_profile.take(), current_cred_process.take()) {
                if cp.contains("aws-okta-processor") || cp.contains("aws_okta_processor") {
                    entries.push(parse_okta_processor_line(&name, &cp));
                }
            }
            current_profile = Some(caps[1].to_owned());
            current_cred_process = None;
        } else if trimmed.starts_with("credential_process") {
            if let Some(value) = trimmed.split_once('=').map(|(_, v)| v.trim()) {
                current_cred_process = Some(value.to_owned());
            }
        }
    }

    // Flush last profile
    if let (Some(name), Some(cp)) = (current_profile, current_cred_process) {
        if cp.contains("aws-okta-processor") || cp.contains("aws_okta_processor") {
            entries.push(parse_okta_processor_line(&name, &cp));
        }
    }

    entries
}

fn parse_okta_processor_line(profile_name: &str, command_line: &str) -> OktaProcessorEntry {
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
        application: extract_flag(command_line, "application"),
        role: extract_flag(command_line, "role"),
        factor: extract_flag(command_line, "factor"),
        duration: extract_flag(command_line, "duration").and_then(|d| d.parse().ok()),
        secondary_role: extract_flag(command_line, "secondary-role"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_managed_block_no_region() {
        let block = build_managed_block("prod", "/usr/local/bin/awsenc", None);
        assert!(block.contains("[profile prod]"));
        assert!(block.contains("credential_process = /usr/local/bin/awsenc serve --profile prod"));
        assert!(block.contains("BEGIN awsenc managed (prod)"));
        assert!(block.contains("END awsenc managed (prod)"));
        assert!(!block.contains("region"));
    }

    #[test]
    fn build_managed_block_with_region() {
        let block = build_managed_block("prod", "/usr/local/bin/awsenc", Some("us-west-2"));
        assert!(block.contains("region = us-west-2"));
    }

    #[test]
    fn upsert_managed_block_append() {
        let existing = "[profile other]\nsome = value\n";
        let block = build_managed_block("new", "/bin/awsenc", None);
        let result = upsert_managed_block(existing, "new", &block);
        assert!(result.contains("[profile other]"));
        assert!(result.contains("[profile new]"));
    }

    #[test]
    fn upsert_managed_block_replace() {
        let block1 = build_managed_block("prod", "/old/path", None);
        let existing = format!("before\n{block1}\nafter\n");
        let block2 = build_managed_block("prod", "/new/path", Some("us-east-1"));
        let result = upsert_managed_block(&existing, "prod", &block2);
        assert!(result.contains("/new/path"));
        assert!(!result.contains("/old/path"));
        assert!(result.contains("before"));
        assert!(result.contains("after"));
    }

    #[test]
    fn remove_managed_block_present() {
        let block = build_managed_block("test", "/bin/awsenc", None);
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
    }

    #[test]
    fn find_okta_processor_entries_none() {
        let content = "[profile something]\nkey = value\n";
        let entries = find_okta_processor_entries(content);
        assert!(entries.is_empty());
    }

    #[test]
    fn upsert_managed_block_empty_existing() {
        let block = build_managed_block("test", "/bin/awsenc", None);
        let result = upsert_managed_block("", "test", &block);
        assert!(result.contains("[profile test]"));
    }
}
