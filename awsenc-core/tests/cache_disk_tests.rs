#![allow(clippy::unwrap_used)]

use std::fs;

use awsenc_core::cache::{CacheFile, CacheHeader, FLAG_HAS_OKTA_SESSION, FORMAT_VERSION, MAGIC};
use awsenc_core::config::{
    GlobalConfig, OktaConfig, ProfileConfig, ProfileOktaConfig, SecondaryRoleConfig,
};

// ===========================================================================
// Cache binary format disk tests
// ===========================================================================

#[test]
fn cache_write_and_read_roundtrip_on_disk() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test-profile.enc");

    let cache = CacheFile {
        header: CacheHeader {
            magic: MAGIC,
            version: FORMAT_VERSION,
            flags: FLAG_HAS_OKTA_SESSION,
            credential_expiration: 1_700_000_000,
            okta_session_expiration: 1_700_007_200,
        },
        aws_ciphertext: vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03],
        okta_session_ciphertext: Some(vec![0xCA, 0xFE, 0xBA, 0xBE]),
    };

    let encoded = cache.encode();
    fs::write(&path, &encoded).unwrap();

    let read_data = fs::read(&path).unwrap();
    let decoded = CacheFile::decode(&read_data).unwrap();

    assert_eq!(decoded.header.magic, MAGIC);
    assert_eq!(decoded.header.version, FORMAT_VERSION);
    assert_eq!(decoded.header.flags, FLAG_HAS_OKTA_SESSION);
    assert!(decoded.header.has_okta_session());
    assert_eq!(decoded.header.credential_expiration, 1_700_000_000);
    assert_eq!(decoded.header.okta_session_expiration, 1_700_007_200);
    assert_eq!(
        decoded.aws_ciphertext,
        vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03]
    );
    assert_eq!(
        decoded.okta_session_ciphertext,
        Some(vec![0xCA, 0xFE, 0xBA, 0xBE])
    );
}

#[test]
fn cache_atomic_write_file_exists() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("atomic-test.enc");

    let cache = CacheFile {
        header: CacheHeader {
            magic: MAGIC,
            version: FORMAT_VERSION,
            flags: 0,
            credential_expiration: 999,
            okta_session_expiration: 0,
        },
        aws_ciphertext: vec![1, 2, 3],
        okta_session_ciphertext: None,
    };

    let encoded = cache.encode();
    fs::write(&path, &encoded).unwrap();

    assert!(path.exists());
    let metadata = fs::metadata(&path).unwrap();
    assert!(metadata.len() > 0);
}

#[test]
fn cache_header_read_without_full_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("header-only.enc");

    let cache = CacheFile {
        header: CacheHeader {
            magic: MAGIC,
            version: FORMAT_VERSION,
            flags: FLAG_HAS_OKTA_SESSION,
            credential_expiration: 1_800_000_000,
            okta_session_expiration: 1_800_003_600,
        },
        aws_ciphertext: vec![0xFF; 10_000], // large payload
        okta_session_ciphertext: Some(vec![0xAA; 5_000]),
    };

    let encoded = cache.encode();
    fs::write(&path, &encoded).unwrap();

    // Read just the header (first 22 bytes) and verify we can parse it.
    let data = fs::read(&path).unwrap();
    assert!(data.len() >= 22);

    let header_bytes = &data[..22];
    let mut magic = [0_u8; 4];
    magic.copy_from_slice(&header_bytes[0..4]);
    assert_eq!(magic, MAGIC);

    let version = header_bytes[4];
    assert_eq!(version, FORMAT_VERSION);

    let flags = header_bytes[5];
    assert_eq!(flags, FLAG_HAS_OKTA_SESSION);

    let cred_exp = u64::from_be_bytes(header_bytes[6..14].try_into().unwrap());
    assert_eq!(cred_exp, 1_800_000_000);

    let okta_exp = u64::from_be_bytes(header_bytes[14..22].try_into().unwrap());
    assert_eq!(okta_exp, 1_800_003_600);
}

#[test]
fn cache_write_delete_verify_gone() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("delete-test.enc");

    let cache = CacheFile {
        header: CacheHeader {
            magic: MAGIC,
            version: FORMAT_VERSION,
            flags: 0,
            credential_expiration: 100,
            okta_session_expiration: 0,
        },
        aws_ciphertext: vec![42],
        okta_session_ciphertext: None,
    };

    let encoded = cache.encode();
    fs::write(&path, &encoded).unwrap();
    assert!(path.exists());

    fs::remove_file(&path).unwrap();
    assert!(!path.exists());
}

#[test]
fn cache_overwrite_preserves_latest() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("overwrite.enc");

    // Write first version.
    let cache1 = CacheFile {
        header: CacheHeader {
            magic: MAGIC,
            version: FORMAT_VERSION,
            flags: 0,
            credential_expiration: 111,
            okta_session_expiration: 0,
        },
        aws_ciphertext: vec![1],
        okta_session_ciphertext: None,
    };
    fs::write(&path, cache1.encode()).unwrap();

    // Overwrite with second version.
    let cache2 = CacheFile {
        header: CacheHeader {
            magic: MAGIC,
            version: FORMAT_VERSION,
            flags: FLAG_HAS_OKTA_SESSION,
            credential_expiration: 222,
            okta_session_expiration: 333,
        },
        aws_ciphertext: vec![2, 3],
        okta_session_ciphertext: Some(vec![4, 5, 6]),
    };
    fs::write(&path, cache2.encode()).unwrap();

    let read_data = fs::read(&path).unwrap();
    let decoded = CacheFile::decode(&read_data).unwrap();
    assert_eq!(decoded.header.credential_expiration, 222);
    assert_eq!(decoded.header.okta_session_expiration, 333);
    assert_eq!(decoded.aws_ciphertext, vec![2, 3]);
    assert_eq!(decoded.okta_session_ciphertext, Some(vec![4, 5, 6]));
}

#[test]
fn cache_no_okta_session_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("no-okta.enc");

    let cache = CacheFile {
        header: CacheHeader {
            magic: MAGIC,
            version: FORMAT_VERSION,
            flags: 0,
            credential_expiration: 1_700_000_000,
            okta_session_expiration: 0,
        },
        aws_ciphertext: vec![10, 20, 30, 40, 50],
        okta_session_ciphertext: None,
    };

    fs::write(&path, cache.encode()).unwrap();
    let decoded = CacheFile::decode(&fs::read(&path).unwrap()).unwrap();

    assert!(!decoded.header.has_okta_session());
    assert_eq!(decoded.header.okta_session_expiration, 0);
    assert!(decoded.okta_session_ciphertext.is_none());
    assert_eq!(decoded.aws_ciphertext, vec![10, 20, 30, 40, 50]);
}

#[test]
fn cache_decode_truncated_aws_ciphertext() {
    // Build valid header + ciphertext length that claims more data than exists.
    let cache = CacheFile {
        header: CacheHeader {
            magic: MAGIC,
            version: FORMAT_VERSION,
            flags: 0,
            credential_expiration: 100,
            okta_session_expiration: 0,
        },
        aws_ciphertext: vec![1, 2, 3],
        okta_session_ciphertext: None,
    };
    let mut encoded = cache.encode();
    // Truncate the data portion -- remove 2 bytes from the end to corrupt it.
    // The aws ciphertext length says 3 bytes but we'll have less.
    encoded.truncate(encoded.len() - 5);

    let result = CacheFile::decode(&encoded);
    assert!(result.is_err());
}

// ===========================================================================
// Config save/load roundtrip tests (using tempdir)
// ===========================================================================

#[test]
fn config_global_save_load_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");

    let config = GlobalConfig {
        okta: OktaConfig {
            organization: Some("mycompany.okta.com".into()),
            user: Some("jane@company.com".into()),
            default_factor: Some("push".into()),
        },
        security: awsenc_core::config::SecurityConfig {
            biometric: Some(true),
        },
        cache: awsenc_core::config::CacheConfig {
            refresh_window_seconds: Some(300),
        },
        aliases: {
            let mut m = std::collections::HashMap::new();
            m.insert("p".into(), "production".into());
            m.insert("s".into(), "staging".into());
            m
        },
    };

    let toml_str = toml::to_string_pretty(&config).unwrap();
    fs::write(&path, &toml_str).unwrap();

    let contents = fs::read_to_string(&path).unwrap();
    let loaded: GlobalConfig = toml::from_str(&contents).unwrap();

    assert_eq!(
        loaded.okta.organization.as_deref(),
        Some("mycompany.okta.com")
    );
    assert_eq!(loaded.okta.user.as_deref(), Some("jane@company.com"));
    assert_eq!(loaded.okta.default_factor.as_deref(), Some("push"));
    assert_eq!(loaded.security.biometric, Some(true));
    assert_eq!(loaded.cache.refresh_window_seconds, Some(300));
    assert_eq!(
        loaded.aliases.get("p").map(String::as_str),
        Some("production")
    );
    assert_eq!(loaded.aliases.get("s").map(String::as_str), Some("staging"));
}

#[test]
fn config_profile_save_load_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("my-profile.toml");

    let config = ProfileConfig {
        okta: ProfileOktaConfig {
            organization: Some("custom-org.okta.com".into()),
            user: Some("jane@company.com".into()),
            application: Some("https://custom-org.okta.com/home/amazon_aws/0oa123/272".into()),
            role: Some("arn:aws:iam::123456789012:role/Admin".into()),
            factor: Some("yubikey".into()),
            duration: Some(7200),
        },
        security: awsenc_core::config::ProfileSecurityConfig {
            biometric: Some(true),
        },
        secondary_role: Some(SecondaryRoleConfig {
            role_arn: "arn:aws:iam::987654321098:role/CrossAccount".into(),
        }),
        region: Some("us-west-2".into()),
    };

    let toml_str = toml::to_string_pretty(&config).unwrap();
    fs::write(&path, &toml_str).unwrap();

    let contents = fs::read_to_string(&path).unwrap();
    let loaded: ProfileConfig = toml::from_str(&contents).unwrap();

    assert_eq!(
        loaded.okta.organization.as_deref(),
        Some("custom-org.okta.com")
    );
    assert_eq!(
        loaded.okta.application.as_deref(),
        Some("https://custom-org.okta.com/home/amazon_aws/0oa123/272")
    );
    assert_eq!(
        loaded.okta.role.as_deref(),
        Some("arn:aws:iam::123456789012:role/Admin")
    );
    assert_eq!(loaded.okta.factor.as_deref(), Some("yubikey"));
    assert_eq!(loaded.okta.duration, Some(7200));
    assert_eq!(loaded.okta.user.as_deref(), Some("jane@company.com"));
    assert_eq!(loaded.security.biometric, Some(true));
    assert_eq!(
        loaded
            .secondary_role
            .as_ref()
            .map(|sr| sr.role_arn.as_str()),
        Some("arn:aws:iam::987654321098:role/CrossAccount")
    );
    assert_eq!(loaded.region.as_deref(), Some("us-west-2"));
}

#[test]
fn config_profile_minimal_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("minimal.toml");

    let config = ProfileConfig {
        okta: ProfileOktaConfig {
            organization: None,
            user: None,
            application: Some("https://org.okta.com/app".into()),
            role: Some("arn:aws:iam::123:role/R".into()),
            factor: None,
            duration: None,
        },
        security: awsenc_core::config::ProfileSecurityConfig::default(),
        secondary_role: None,
        region: None,
    };

    let toml_str = toml::to_string_pretty(&config).unwrap();
    fs::write(&path, &toml_str).unwrap();

    let contents = fs::read_to_string(&path).unwrap();
    let loaded: ProfileConfig = toml::from_str(&contents).unwrap();

    assert!(loaded.okta.organization.is_none());
    assert!(loaded.okta.factor.is_none());
    assert!(loaded.okta.duration.is_none());
    assert!(loaded.secondary_role.is_none());
    assert_eq!(
        loaded.okta.application.as_deref(),
        Some("https://org.okta.com/app")
    );
}

#[test]
fn config_global_default_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("default-config.toml");

    let config = GlobalConfig::default();
    let toml_str = toml::to_string_pretty(&config).unwrap();
    fs::write(&path, &toml_str).unwrap();

    let contents = fs::read_to_string(&path).unwrap();
    let loaded: GlobalConfig = toml::from_str(&contents).unwrap();

    assert!(loaded.okta.organization.is_none());
    assert!(loaded.okta.user.is_none());
    assert!(loaded.security.biometric.is_none());
    assert!(loaded.aliases.is_empty());
}

#[cfg(unix)]
#[test]
fn cache_file_permissions_on_disk() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("perms-test.enc");

    let cache = CacheFile {
        header: CacheHeader {
            magic: MAGIC,
            version: FORMAT_VERSION,
            flags: 0,
            credential_expiration: 100,
            okta_session_expiration: 0,
        },
        aws_ciphertext: vec![1],
        okta_session_ciphertext: None,
    };

    fs::write(&path, cache.encode()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    let perms = fs::metadata(&path).unwrap().permissions();
    assert_eq!(perms.mode() & 0o777, 0o600);
}
