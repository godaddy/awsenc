use std::path::PathBuf;

use enclaveapp_cache::{CacheEntry, CacheFormat};
use enclaveapp_core::metadata;

use crate::{Error, Result};

/// Magic bytes: "AWSE"
pub const MAGIC: [u8; 4] = [0x41, 0x57, 0x53, 0x45];
/// Current binary cache format version.
pub const FORMAT_VERSION: u8 = 0x01;
/// Flag indicating the cache contains an encrypted Okta session.
pub const FLAG_HAS_OKTA_SESSION: u8 = 0x01;

/// App-specific header data length: 8 (credential_expiration) + 8 (okta_session_expiration).
const HEADER_DATA_LEN: usize = 16;

/// Shared cache format instance for awsenc.
fn cache_format() -> CacheFormat {
    CacheFormat::new(MAGIC, FORMAT_VERSION)
}

/// Parsed cache file header (for status display without loading ciphertext).
#[derive(Debug, Clone)]
pub struct CacheHeader {
    pub magic: [u8; 4],
    pub version: u8,
    pub flags: u8,
    pub credential_expiration: u64,
    pub okta_session_expiration: u64,
}

impl CacheHeader {
    pub fn has_okta_session(&self) -> bool {
        self.flags & FLAG_HAS_OKTA_SESSION != 0
    }
}

/// Complete cache file: header + encrypted payloads.
#[derive(Debug, Clone)]
pub struct CacheFile {
    pub header: CacheHeader,
    pub aws_ciphertext: Vec<u8>,
    pub okta_session_ciphertext: Option<Vec<u8>>,
}

impl CacheFile {
    /// Serialize to the binary cache format.
    pub fn encode(&self) -> Vec<u8> {
        let mut header_data = Vec::with_capacity(HEADER_DATA_LEN);
        header_data.extend_from_slice(&self.header.credential_expiration.to_be_bytes());
        header_data.extend_from_slice(&self.header.okta_session_expiration.to_be_bytes());

        let mut blobs = vec![self.aws_ciphertext.clone()];
        match self.okta_session_ciphertext {
            Some(ref okta) => blobs.push(okta.clone()),
            None => blobs.push(vec![]),
        }

        let entry = CacheEntry {
            flags: self.header.flags,
            header_data,
            blobs,
        };

        cache_format().encode(&entry)
    }

    /// Deserialize from the binary cache format.
    pub fn decode(data: &[u8]) -> Result<Self> {
        let entry = cache_format()
            .decode(data, HEADER_DATA_LEN)
            .map_err(|e| Error::CacheFormat(e.to_string()))?;

        let credential_expiration =
            u64::from_be_bytes(entry.header_data[0..8].try_into().map_err(|_| {
                Error::CacheFormat("bad credential expiration in header_data".into())
            })?);
        let okta_session_expiration =
            u64::from_be_bytes(entry.header_data[8..16].try_into().map_err(|_| {
                Error::CacheFormat("bad okta session expiration in header_data".into())
            })?);

        let header = CacheHeader {
            magic: MAGIC,
            version: FORMAT_VERSION,
            flags: entry.flags,
            credential_expiration,
            okta_session_expiration,
        };

        let aws_ciphertext = entry.blobs.first().cloned().unwrap_or_default();
        let okta_session_ciphertext = entry.blobs.get(1).filter(|b| !b.is_empty()).cloned();

        Ok(CacheFile {
            header,
            aws_ciphertext,
            okta_session_ciphertext,
        })
    }
}

// ---------------------------------------------------------------------------
// File I/O
// ---------------------------------------------------------------------------

/// Returns the cache file path for a profile: `~/.config/awsenc/<profile>.enc`
pub fn cache_path(profile: &str) -> Result<PathBuf> {
    let sanitized = sanitize_profile_name(profile)?;
    let dir = crate::config::config_dir()?;
    Ok(dir.join(format!("{sanitized}.enc")))
}

/// Read the full cache file from disk. Returns `None` if the file does not exist.
pub fn read_cache(profile: &str) -> Result<Option<CacheFile>> {
    let path = cache_path(profile)?;
    if !path.exists() {
        return Ok(None);
    }
    let data = std::fs::read(&path)?;
    CacheFile::decode(&data).map(Some)
}

/// Write a cache file atomically (write to temp file, then rename).
/// Sets 0o600 permissions on Unix.
pub fn write_cache(profile: &str, cache: &CacheFile) -> Result<()> {
    let path = cache_path(profile)?;
    let encoded = cache.encode();
    metadata::atomic_write(&path, &encoded)
        .map_err(|e| Error::CacheFormat(format!("failed to write cache: {e}")))?;
    #[cfg(unix)]
    {
        metadata::restrict_file_permissions(&path)
            .map_err(|e| Error::CacheFormat(format!("failed to secure cache: {e}")))?;
    }
    Ok(())
}

/// Read just the header from a cache file (for status display without loading ciphertext).
pub fn read_cache_header(profile: &str) -> Result<Option<CacheHeader>> {
    let path = cache_path(profile)?;
    if !path.exists() {
        return Ok(None);
    }

    let (flags, header_data) = cache_format()
        .read_header(&path, HEADER_DATA_LEN)
        .map_err(|e| Error::CacheFormat(e.to_string()))?
        .ok_or_else(|| Error::CacheFormat("cache file disappeared during read".into()))?;

    let credential_expiration = u64::from_be_bytes(
        header_data[0..8]
            .try_into()
            .map_err(|_| Error::CacheFormat("bad header".into()))?,
    );
    let okta_session_expiration = u64::from_be_bytes(
        header_data[8..16]
            .try_into()
            .map_err(|_| Error::CacheFormat("bad header".into()))?,
    );

    Ok(Some(CacheHeader {
        magic: MAGIC,
        version: FORMAT_VERSION,
        flags,
        credential_expiration,
        okta_session_expiration,
    }))
}

/// Delete the cache file for a profile.
pub fn delete_cache(profile: &str) -> Result<()> {
    let path = cache_path(profile)?;
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    Ok(())
}

/// Validate a profile name: alphanumeric, hyphens, underscores only, max 64 characters.
pub fn sanitize_profile_name(name: &str) -> Result<String> {
    Ok(crate::config::validate_profile_name(name)?.to_owned())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn sanitize_valid_names() {
        assert_eq!(sanitize_profile_name("prod").unwrap(), "prod");
        assert_eq!(sanitize_profile_name("my-profile").unwrap(), "my-profile");
        assert_eq!(sanitize_profile_name("profile_1").unwrap(), "profile_1");
        assert_eq!(sanitize_profile_name("a-b_c-123").unwrap(), "a-b_c-123");
    }

    #[test]
    fn sanitize_rejects_empty() {
        assert!(sanitize_profile_name("").is_err());
    }

    #[test]
    fn sanitize_rejects_too_long() {
        let long_name = "a".repeat(65);
        assert!(sanitize_profile_name(&long_name).is_err());
    }

    #[test]
    fn sanitize_rejects_special_chars() {
        assert!(sanitize_profile_name("../etc/passwd").is_err());
        assert!(sanitize_profile_name("profile name").is_err());
        assert!(sanitize_profile_name("profile.name").is_err());
        assert!(sanitize_profile_name("profile/name").is_err());
    }

    #[test]
    fn sanitize_max_length_ok() {
        let name = "a".repeat(64);
        assert!(sanitize_profile_name(&name).is_ok());
    }

    #[test]
    fn cache_encode_decode_roundtrip_no_okta() {
        let cache = CacheFile {
            header: CacheHeader {
                magic: MAGIC,
                version: FORMAT_VERSION,
                flags: 0,
                credential_expiration: 1_700_000_000,
                okta_session_expiration: 0,
            },
            aws_ciphertext: vec![1, 2, 3, 4, 5],
            okta_session_ciphertext: None,
        };

        let encoded = cache.encode();
        let decoded = CacheFile::decode(&encoded).unwrap();

        assert_eq!(decoded.header.magic, MAGIC);
        assert_eq!(decoded.header.version, FORMAT_VERSION);
        assert_eq!(decoded.header.flags, 0);
        assert_eq!(decoded.header.credential_expiration, 1_700_000_000);
        assert_eq!(decoded.aws_ciphertext, vec![1, 2, 3, 4, 5]);
        assert!(decoded.okta_session_ciphertext.is_none());
    }

    #[test]
    fn cache_encode_decode_roundtrip_with_okta() {
        let cache = CacheFile {
            header: CacheHeader {
                magic: MAGIC,
                version: FORMAT_VERSION,
                flags: FLAG_HAS_OKTA_SESSION,
                credential_expiration: 1_700_000_000,
                okta_session_expiration: 1_700_007_200,
            },
            aws_ciphertext: vec![10, 20, 30],
            okta_session_ciphertext: Some(vec![40, 50, 60, 70]),
        };

        let encoded = cache.encode();
        let decoded = CacheFile::decode(&encoded).unwrap();

        assert!(decoded.header.has_okta_session());
        assert_eq!(decoded.header.okta_session_expiration, 1_700_007_200);
        assert_eq!(decoded.aws_ciphertext, vec![10, 20, 30]);
        assert_eq!(decoded.okta_session_ciphertext, Some(vec![40, 50, 60, 70]));
    }

    #[test]
    fn cache_decode_bad_magic() {
        let data = vec![
            0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        assert!(CacheFile::decode(&data).is_err());
    }

    #[test]
    fn cache_decode_bad_version() {
        let mut data = vec![0x41, 0x57, 0x53, 0x45, 0xFF, 0x00];
        data.extend_from_slice(&[0_u8; 20]);
        assert!(CacheFile::decode(&data).is_err());
    }

    #[test]
    fn cache_decode_truncated() {
        let data = vec![0x41, 0x57, 0x53, 0x45];
        assert!(CacheFile::decode(&data).is_err());
    }

    #[test]
    fn cache_path_valid_profile() {
        let path = cache_path("my-profile").unwrap();
        assert!(path.to_str().is_some_and(|s| s.ends_with("my-profile.enc")));
    }

    #[test]
    fn cache_path_invalid_profile() {
        assert!(cache_path("../bad").is_err());
    }

    #[test]
    fn header_has_okta_session_flag() {
        let header = CacheHeader {
            magic: MAGIC,
            version: FORMAT_VERSION,
            flags: FLAG_HAS_OKTA_SESSION,
            credential_expiration: 0,
            okta_session_expiration: 0,
        };
        assert!(header.has_okta_session());

        let header2 = CacheHeader { flags: 0, ..header };
        assert!(!header2.has_okta_session());
    }

    #[test]
    fn write_cache_ignores_preexisting_legacy_tmp_file() {
        let _lock = crate::TEST_ENV_MUTEX.lock().expect("mutex poisoned");
        let dir = tempfile::tempdir().unwrap();
        let prev_home = std::env::var("HOME").ok();
        let prev_xdg = std::env::var("XDG_CONFIG_HOME").ok();
        std::env::set_var("HOME", dir.path());
        std::env::set_var("XDG_CONFIG_HOME", dir.path().join(".config"));
        let path = cache_path("tmp-test").unwrap();
        let temp_path = path.parent().unwrap().join(".tmp-test.enc.tmp");
        std::fs::write(&temp_path, b"stale").unwrap();

        let cache = CacheFile {
            header: CacheHeader {
                magic: MAGIC,
                version: FORMAT_VERSION,
                flags: 0,
                credential_expiration: 1,
                okta_session_expiration: 0,
            },
            aws_ciphertext: vec![1, 2, 3],
            okta_session_ciphertext: None,
        };

        write_cache("tmp-test", &cache).unwrap();
        let loaded = read_cache("tmp-test").unwrap().unwrap();
        assert_eq!(loaded.aws_ciphertext, vec![1, 2, 3]);
        match prev_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
        match prev_xdg {
            Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
            None => std::env::remove_var("XDG_CONFIG_HOME"),
        }
    }

    #[test]
    fn encode_large_ciphertext() {
        let big = vec![0xAB; 100_000];
        let cache = CacheFile {
            header: CacheHeader {
                magic: MAGIC,
                version: FORMAT_VERSION,
                flags: 0,
                credential_expiration: 999,
                okta_session_expiration: 0,
            },
            aws_ciphertext: big.clone(),
            okta_session_ciphertext: None,
        };
        let encoded = cache.encode();
        let decoded = CacheFile::decode(&encoded).unwrap();
        assert_eq!(decoded.aws_ciphertext.len(), 100_000);
        assert_eq!(decoded.aws_ciphertext, big);
    }

    #[test]
    fn cache_decode_corrupted_magic_xwse() {
        // "XWSE" instead of "AWSE"
        let mut data = vec![0x58, 0x57, 0x53, 0x45, FORMAT_VERSION, 0x00];
        data.extend_from_slice(&[0_u8; 16]); // credential_expiration + okta_session_expiration
        data.extend_from_slice(&0_u32.to_be_bytes()); // aws ciphertext len
        data.extend_from_slice(&0_u32.to_be_bytes()); // okta ciphertext len
        assert!(CacheFile::decode(&data).is_err());
    }

    #[test]
    fn cache_decode_truncated_header_less_than_header_size() {
        // Correct magic + version but fewer than HEADER_SIZE + 4 bytes total
        let data = vec![0x41, 0x57, 0x53, 0x45, FORMAT_VERSION, 0x00, 0x00, 0x00];
        assert!(
            CacheFile::decode(&data).is_err(),
            "data shorter than HEADER_SIZE + 4 should return error"
        );
    }

    #[test]
    fn cache_expiration_timestamp_preserved() {
        let expiration: u64 = 1_700_123_456;
        let okta_exp: u64 = 1_700_234_567;
        let cache = CacheFile {
            header: CacheHeader {
                magic: MAGIC,
                version: FORMAT_VERSION,
                flags: FLAG_HAS_OKTA_SESSION,
                credential_expiration: expiration,
                okta_session_expiration: okta_exp,
            },
            aws_ciphertext: vec![0xDE, 0xAD],
            okta_session_ciphertext: Some(vec![0xBE, 0xEF]),
        };
        let encoded = cache.encode();
        let decoded = CacheFile::decode(&encoded).unwrap();
        assert_eq!(decoded.header.credential_expiration, expiration);
        assert_eq!(decoded.header.okta_session_expiration, okta_exp);
    }

    #[test]
    fn cache_decode_truncated_aws_ciphertext_data() {
        // Valid header claiming 100 bytes of AWS ciphertext but only 5 present
        let mut data = Vec::new();
        data.extend_from_slice(&MAGIC);
        data.push(FORMAT_VERSION);
        data.push(0x00); // flags
        data.extend_from_slice(&1_700_000_000_u64.to_be_bytes());
        data.extend_from_slice(&0_u64.to_be_bytes());
        data.extend_from_slice(&100_u32.to_be_bytes()); // claims 100 bytes
        data.extend_from_slice(&[0xAA; 5]); // only 5
        assert!(CacheFile::decode(&data).is_err());
    }

    #[test]
    fn cache_decode_empty_ciphertexts_roundtrip() {
        let cache = CacheFile {
            header: CacheHeader {
                magic: MAGIC,
                version: FORMAT_VERSION,
                flags: 0,
                credential_expiration: 0,
                okta_session_expiration: 0,
            },
            aws_ciphertext: vec![],
            okta_session_ciphertext: None,
        };
        let encoded = cache.encode();
        let decoded = CacheFile::decode(&encoded).unwrap();
        assert!(decoded.aws_ciphertext.is_empty());
        assert!(decoded.okta_session_ciphertext.is_none());
    }
}
