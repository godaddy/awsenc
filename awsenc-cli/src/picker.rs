use std::io::{IsTerminal, Write};

use chrono::Utc;
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::terminal;

use awsenc_core::credential::CredentialState;
use awsenc_core::profile::ProfileInfo;

use crate::usage::UsageData;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Interactive profile picker.
///
/// Displays MRU profiles first, then all remaining profiles alphabetically.
/// Supports number selection and type-to-filter.
/// Returns the name of the selected profile.
pub fn pick_profile(
    profiles: &[ProfileInfo],
    usage: &UsageData,
    active_profile: Option<&str>,
) -> Result<String> {
    if !std::io::stdin().is_terminal() {
        return Err("interactive profile selection requires a TTY".into());
    }

    if profiles.is_empty() {
        return Err("no profiles configured; run 'awsenc install' first".into());
    }

    // Build the ordered display list: MRU first, then alphabetical remainder
    let mru_names = crate::usage::get_mru_profiles(usage, 5);
    let mut display: Vec<&ProfileInfo> = Vec::with_capacity(profiles.len());

    for mru_name in &mru_names {
        if let Some(info) = profiles.iter().find(|p| &p.name == mru_name) {
            display.push(info);
        }
    }

    let mut remaining: Vec<&ProfileInfo> = profiles
        .iter()
        .filter(|p| !mru_names.contains(&p.name))
        .collect();
    remaining.sort_by(|a, b| a.name.cmp(&b.name));

    let mru_count = display.len();
    display.extend(remaining);

    let mut filter = String::new();

    loop {
        let filtered: Vec<(usize, &ProfileInfo)> = if filter.is_empty() {
            display.iter().enumerate().map(|(i, p)| (i, *p)).collect()
        } else {
            let lower_filter = filter.to_lowercase();
            display
                .iter()
                .enumerate()
                .filter(|(_, p)| p.name.to_lowercase().contains(&lower_filter))
                .map(|(i, p)| (i, *p))
                .collect()
        };

        // Auto-select if exactly one match with a non-empty filter
        if filtered.len() == 1 && !filter.is_empty() {
            return Ok(filtered[0].1.name.clone());
        }

        render_list(&filtered, &filter, mru_count, active_profile)?;

        terminal::enable_raw_mode()?;
        let key_event = loop {
            if let Event::Key(ke) = event::read()? {
                break ke;
            }
        };
        terminal::disable_raw_mode()?;

        match key_event.code {
            KeyCode::Char('c') if key_event.modifiers.contains(KeyModifiers::CONTROL) => {
                return Err("cancelled".into());
            }
            KeyCode::Esc => {
                filter.clear();
            }
            KeyCode::Backspace => {
                filter.pop();
            }
            KeyCode::Enter => {
                if filtered.len() == 1 {
                    return Ok(filtered[0].1.name.clone());
                }
                if let Ok(n) = filter.trim().parse::<usize>() {
                    if n >= 1 && n <= filtered.len() {
                        return Ok(filtered[n - 1].1.name.clone());
                    }
                }
            }
            KeyCode::Char(c) => {
                filter.push(c);
                if let Ok(n) = filter.trim().parse::<usize>() {
                    let total = display.len();
                    if n >= 1 && n <= total {
                        let digits = filter.len();
                        let max_possible = n * 10;
                        if max_possible > total || digits >= total.to_string().len() {
                            return Ok(display[n - 1].name.clone());
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

#[allow(clippy::print_stderr)]
fn render_list(
    filtered: &[(usize, &ProfileInfo)],
    filter: &str,
    mru_count: usize,
    active_profile: Option<&str>,
) -> Result<()> {
    let stderr = std::io::stderr();
    let mut err = stderr.lock();

    write!(err, "\x1b[2J\x1b[H")?;

    if mru_count > 0 && filter.is_empty() {
        writeln!(err, "  Recent profiles:")?;
    }

    for (display_idx, (original_idx, info)) in filtered.iter().enumerate() {
        if filter.is_empty() && *original_idx == mru_count && mru_count > 0 {
            writeln!(err)?;
            writeln!(err, "  All profiles:")?;
        }

        let num = display_idx + 1;
        let active_marker = if active_profile == Some(info.name.as_str()) {
            " *"
        } else {
            "  "
        };
        let status = format_status(info);
        writeln!(
            err,
            "  {num:>3}. {:<28}{active_marker} ({status})",
            info.name
        )?;
    }

    if filtered.is_empty() {
        writeln!(err, "  (no matching profiles)")?;
    }

    writeln!(err)?;
    if filter.is_empty() {
        write!(
            err,
            "  Select profile [1-{}] or type to filter: ",
            filtered.len()
        )?;
    } else {
        write!(err, "  Filter [{filter}] (Esc to clear, Enter to select): ")?;
    }
    err.flush()?;

    Ok(())
}

fn format_status(info: &ProfileInfo) -> String {
    match info.cache_state {
        Some(CredentialState::Fresh | CredentialState::Refresh) => {
            if let Some(exp) = info.expiration {
                let remaining = exp.signed_duration_since(Utc::now());
                let mins = remaining.num_minutes();
                if mins >= 60 {
                    format!("authenticated, expires in {}h {}m", mins / 60, mins % 60)
                } else if mins > 0 {
                    format!("authenticated, expires in {mins}m")
                } else {
                    "expired".to_owned()
                }
            } else {
                "authenticated".to_owned()
            }
        }
        Some(CredentialState::Expired) => "expired".to_owned(),
        None => "not cached".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_profile(name: &str, state: Option<CredentialState>) -> ProfileInfo {
        ProfileInfo {
            name: name.to_owned(),
            has_config: true,
            cache_state: state,
            expiration: state.map(|_| Utc::now() + chrono::Duration::minutes(45)),
            okta_session_expiration: None,
        }
    }

    #[test]
    fn format_status_fresh() {
        let info = make_profile("test", Some(CredentialState::Fresh));
        let status = format_status(&info);
        assert!(status.contains("authenticated"));
        assert!(status.contains("expires in"));
    }

    #[test]
    fn format_status_expired() {
        let info = ProfileInfo {
            name: "test".into(),
            has_config: true,
            cache_state: Some(CredentialState::Expired),
            expiration: Some(Utc::now() - chrono::Duration::minutes(5)),
            okta_session_expiration: None,
        };
        assert_eq!(format_status(&info), "expired");
    }

    #[test]
    fn format_status_not_cached() {
        let info = ProfileInfo {
            name: "test".into(),
            has_config: true,
            cache_state: None,
            expiration: None,
            okta_session_expiration: None,
        };
        assert_eq!(format_status(&info), "not cached");
    }

    #[test]
    fn format_status_fresh_with_hours() {
        let info = ProfileInfo {
            name: "test".into(),
            has_config: true,
            cache_state: Some(CredentialState::Fresh),
            expiration: Some(Utc::now() + chrono::Duration::hours(2) + chrono::Duration::minutes(30)),
            okta_session_expiration: None,
        };
        let status = format_status(&info);
        assert!(status.contains("2h"), "expected hours in status: {status}");
        assert!(status.contains("m"), "expected minutes in status: {status}");
    }

    #[test]
    fn format_status_refresh_state() {
        let info = ProfileInfo {
            name: "test".into(),
            has_config: true,
            cache_state: Some(CredentialState::Refresh),
            expiration: Some(Utc::now() + chrono::Duration::minutes(5)),
            okta_session_expiration: None,
        };
        let status = format_status(&info);
        assert!(
            status.contains("authenticated"),
            "refresh state should show authenticated: {status}"
        );
    }

    #[test]
    fn format_status_fresh_no_expiration() {
        let info = ProfileInfo {
            name: "test".into(),
            has_config: true,
            cache_state: Some(CredentialState::Fresh),
            expiration: None,
            okta_session_expiration: None,
        };
        let status = format_status(&info);
        assert_eq!(status, "authenticated");
    }

    #[test]
    fn format_status_fresh_just_expired() {
        // Edge case: state is Fresh (or Refresh) but expiration is actually past
        let info = ProfileInfo {
            name: "test".into(),
            has_config: true,
            cache_state: Some(CredentialState::Fresh),
            expiration: Some(Utc::now() - chrono::Duration::seconds(1)),
            okta_session_expiration: None,
        };
        let status = format_status(&info);
        assert_eq!(status, "expired");
    }

    #[test]
    fn pick_profile_empty_returns_error() {
        // Cannot test the interactive picker without a TTY, but we can test
        // the empty profiles case
        let profiles: Vec<ProfileInfo> = vec![];
        let usage = UsageData::default();
        let result = pick_profile(&profiles, &usage, None);
        assert!(result.is_err());
        let err = result.expect_err("should be an error").to_string();
        assert!(
            err.contains("no profiles") || err.contains("TTY"),
            "expected descriptive error, got: {err}"
        );
    }
}
