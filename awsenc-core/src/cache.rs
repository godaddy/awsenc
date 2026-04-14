use std::path::PathBuf;

use crate::{Error, Result};

/// Magic bytes: "AWSE"
pub const MAGIC: [u8; 4] = [0x41, 0x57, 0x53, 0x45];
/// Current binary cache format version.
pub const FORMAT_VERSION: u8 = 0x01;
/// Flag indicating the cache contains an encrypted Okta session.
pub const FLAG_HAS_OKTA_SESSION: u8 = 0x01;

/// Header size in bytes: 4 (magic) + 1 (version) + 1 (flags) + 8 (cred exp) + 8 (okta exp) = 22
const HEADER_SIZE: usize = 22;

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
        let mut buf = Vec::with_capacity(
            HEADER_SIZE
                + 4
                + self.aws_ciphertext.len()
                + 4
                + self.okta_session_ciphertext.as_ref().map_or(0, Vec::len),
        );

        // Header
        buf.extend_from_slice(&self.header.magic);
        buf.push(self.header.version);
        buf.push(self.header.flags);
        buf.extend_from_slice(&self.header.credential_expiration.to_be_bytes());
        buf.extend_from_slice(&self.header.okta_session_expiration.to_be_bytes());

        // AWS ciphertext length + data
        let aws_len = u32::try_from(self.aws_ciphertext.len()).unwrap_or(u32::MAX);
        buf.extend_from_slice(&aws_len.to_be_bytes());
        buf.extend_from_slice(&self.aws_ciphertext);

        // Okta session ciphertext length + data
        if let Some(ref okta) = self.okta_session_ciphertext {
            let okta_len = u32::try_from(okta.len()).unwrap_or(u32::MAX);
            buf.extend_from_slice(&okta_len.to_be_bytes());
            buf.extend_from_slice(okta);
        } else {
            buf.extend_from_slice(&0_u32.to_be_bytes());
        }

        buf
    }

    /// Deserialize from the binary cache format.
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < HEADER_SIZE + 4 {
            return Err(Error::CacheFormat("data too short for cache header".into()));
        }

        let mut magic = [0_u8; 4];
        magic.copy_from_slice(&data[0..4]);
        if magic != MAGIC {
            return Err(Error::CacheFormat(format!(
                "invalid magic bytes: expected AWSE, got {magic:?}"
            )));
        }

        let version = data[4];
        if version != FORMAT_VERSION {
            return Err(Error::CacheFormat(format!(
                "unsupported format version: {version}"
            )));
        }

        let flags = data[5];
        let credential_expiration = u64::from_be_bytes(
            data[6..14]
                .try_into()
                .map_err(|_| Error::CacheFormat("bad credential expiration".into()))?,
        );
        let okta_session_expiration = u64::from_be_bytes(
            data[14..22]
                .try_into()
                .map_err(|_| Error::CacheFormat("bad okta session expiration".into()))?,
        );

        let header = CacheHeader {
            magic,
            version,
            flags,
            credential_expiration,
            okta_session_expiration,
        };

        // AWS ciphertext
        let mut offset = HEADER_SIZE;
        if data.len() < offset + 4 {
            return Err(Error::CacheFormat("truncated AWS ciphertext length".into()));
        }
        let aws_len = u32::from_be_bytes(
            data[offset..offset + 4]
                .try_into()
                .map_err(|_| Error::CacheFormat("bad AWS ciphertext length".into()))?,
        ) as usize;
        offset += 4;

        if data.len() < offset + aws_len {
            return Err(Error::CacheFormat("truncated AWS ciphertext data".into()));
        }
        let aws_ciphertext = data[offset..offset + aws_len].to_vec();
        offset += aws_len;

        // Okta session ciphertext
        let okta_session_ciphertext = if data.len() >= offset + 4 {
            let okta_len = u32::from_be_bytes(
                data[offset..offset + 4]
                    .try_into()
                    .map_err(|_| Error::CacheFormat("bad okta ciphertext length".into()))?,
            ) as usize;
            offset += 4;

            if okta_len > 0 {
                if data.len() < offset + okta_len {
                    return Err(Error::CacheFormat("truncated okta ciphertext data".into()));
                }
                Some(data[offset..offset + okta_len].to_vec())
            } else {
                None
            }
        } else {
            None
        };

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
    let dir = path
        .parent()
        .ok_or_else(|| Error::CacheFormat("cache path has no parent directory".into()))?;

    let encoded = cache.encode();

    // Write to a temp file in the same directory, then rename for atomicity.
    let sanitized = sanitize_profile_name(profile)?;
    let temp_path = dir.join(format!(".{sanitized}.enc.tmp"));
    std::fs::write(&temp_path, &encoded)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&temp_path, std::fs::Permissions::from_mode(0o600))?;
    }

    std::fs::rename(&temp_path, &path)?;
    Ok(())
}

/// Read just the header from a cache file (for status display without loading ciphertext).
pub fn read_cache_header(profile: &str) -> Result<Option<CacheHeader>> {
    let path = cache_path(profile)?;
    if !path.exists() {
        return Ok(None);
    }

    let data = std::fs::read(&path)?;
    if data.len() < HEADER_SIZE {
        return Err(Error::CacheFormat("cache file too short for header".into()));
    }

    let mut magic = [0_u8; 4];
    magic.copy_from_slice(&data[0..4]);
    if magic != MAGIC {
        return Err(Error::CacheFormat("invalid magic bytes".into()));
    }

    let version = data[4];
    if version != FORMAT_VERSION {
        return Err(Error::CacheFormat(format!(
            "unsupported format version: {version}"
        )));
    }

    Ok(Some(CacheHeader {
        magic,
        version,
        flags: data[5],
        credential_expiration: u64::from_be_bytes(
            data[6..14]
                .try_into()
                .map_err(|_| Error::CacheFormat("bad header".into()))?,
        ),
        okta_session_expiration: u64::from_be_bytes(
            data[14..22]
                .try_into()
                .map_err(|_| Error::CacheFormat("bad header".into()))?,
        ),
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
    crate::config::validate_profile_name(name)
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
