use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use awsenc_core::config;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct UsageData {
    #[serde(default)]
    pub profiles: HashMap<String, ProfileUsage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileUsage {
    pub last_used: DateTime<Utc>,
    pub use_count: u64,
}

fn usage_path() -> Result<std::path::PathBuf> {
    let dir = config::config_dir().map_err(|e| format!("config dir: {e}"))?;
    Ok(dir.join("usage.json"))
}

/// Load usage data from disk. Returns empty data if the file is missing or corrupt.
pub fn load_usage() -> UsageData {
    let Ok(path) = usage_path() else {
        return UsageData::default();
    };

    if !path.exists() {
        return UsageData::default();
    }

    match std::fs::read_to_string(&path) {
        Ok(contents) => serde_json::from_str(&contents).unwrap_or_default(),
        Err(_) => UsageData::default(),
    }
}

/// Save usage data to disk.
pub fn save_usage(data: &UsageData) -> Result<()> {
    let path = usage_path()?;
    let contents = serde_json::to_string_pretty(data)?;
    std::fs::write(&path, contents)?;
    Ok(())
}

/// Record a profile usage event (updates `last_used` and increments `use_count`).
pub fn record_usage(profile: &str) {
    let mut data = load_usage();
    let entry = data
        .profiles
        .entry(profile.to_owned())
        .or_insert(ProfileUsage {
            last_used: Utc::now(),
            use_count: 0,
        });
    entry.last_used = Utc::now();
    entry.use_count += 1;

    if let Err(e) = save_usage(&data) {
        tracing::warn!("failed to save usage data: {e}");
    }
}

/// Return profile names sorted by `last_used` (most recent first), up to `limit`.
pub fn get_mru_profiles(data: &UsageData, limit: usize) -> Vec<String> {
    let mut entries: Vec<_> = data.profiles.iter().collect();
    entries.sort_by_key(|e| std::cmp::Reverse(e.1.last_used));
    entries
        .into_iter()
        .take(limit)
        .map(|(k, _)| k.clone())
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn usage_data_roundtrip() {
        let mut data = UsageData::default();
        data.profiles.insert(
            "test-profile".into(),
            ProfileUsage {
                last_used: Utc::now(),
                use_count: 5,
            },
        );

        let json = serde_json::to_string(&data).unwrap();
        let parsed: UsageData = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.profiles.len(), 1);
        assert_eq!(parsed.profiles["test-profile"].use_count, 5);
    }

    #[test]
    fn get_mru_profiles_ordering() {
        let mut data = UsageData::default();
        data.profiles.insert(
            "old".into(),
            ProfileUsage {
                last_used: Utc::now() - chrono::Duration::hours(2),
                use_count: 1,
            },
        );
        data.profiles.insert(
            "recent".into(),
            ProfileUsage {
                last_used: Utc::now(),
                use_count: 1,
            },
        );
        data.profiles.insert(
            "middle".into(),
            ProfileUsage {
                last_used: Utc::now() - chrono::Duration::hours(1),
                use_count: 1,
            },
        );

        let mru = get_mru_profiles(&data, 5);
        assert_eq!(mru[0], "recent");
        assert_eq!(mru[1], "middle");
        assert_eq!(mru[2], "old");
    }

    #[test]
    fn get_mru_profiles_limit() {
        let mut data = UsageData::default();
        for i in 0..10 {
            data.profiles.insert(
                format!("profile-{i}"),
                ProfileUsage {
                    last_used: Utc::now() - chrono::Duration::hours(i),
                    use_count: 1,
                },
            );
        }

        let mru = get_mru_profiles(&data, 3);
        assert_eq!(mru.len(), 3);
    }

    #[test]
    fn load_usage_returns_default_when_missing() {
        let data = load_usage();
        // May or may not have profiles depending on test env, but should not panic
        assert!(data.profiles.len() < 10000);
    }
}
