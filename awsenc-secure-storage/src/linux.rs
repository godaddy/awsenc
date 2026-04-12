use std::fs;
use std::path::PathBuf;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use rand::RngCore;
use tracing::{debug, warn};

use crate::{Result, SecureStorage, StorageError};

/// AES-256-GCM nonce size (96 bits).
const NONCE_SIZE: usize = 12;

/// AES-256 key size in bytes.
const KEY_SIZE: usize = 32;

/// Software-only AES-GCM storage backed by a key file on disk.
///
/// The AES-256 key is stored at `~/.config/awsenc/storage.key` with
/// mode 0o600. This is a fallback for native Linux systems without
/// hardware-backed key storage; it does NOT provide the same security
/// guarantees as Secure Enclave or TPM.
pub struct LinuxKeyringStorage {
    cipher: Aes256Gcm,
}

impl LinuxKeyringStorage {
    /// Create a new Linux keyring storage, loading or generating the AES key.
    ///
    /// Prints a one-time warning to stderr about software-only storage.
    pub fn new() -> Result<Self> {
        warn!(
            "using software-only credential encryption (no TPM or Secure Enclave available); \
             the encryption key is stored on disk at ~/.config/awsenc/storage.key"
        );

        let key_bytes = load_or_generate_key()?;
        let cipher = Aes256Gcm::new_from_slice(&key_bytes).map_err(|e| {
            StorageError::KeyInitFailed(format!("failed to initialize AES-GCM cipher: {e}"))
        })?;

        debug!("Linux keyring storage initialized");
        Ok(Self { cipher })
    }
}

impl SecureStorage for LinuxKeyringStorage {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| StorageError::EncryptionFailed(e.to_string()))?;

        // Prepend nonce: [nonce (12 bytes) | ciphertext + tag]
        let mut output = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < NONCE_SIZE {
            return Err(StorageError::DecryptionFailed(
                "ciphertext too short to contain nonce".into(),
            ));
        }

        let (nonce_bytes, encrypted) = ciphertext.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        self.cipher
            .decrypt(nonce, encrypted)
            .map_err(|e| StorageError::DecryptionFailed(e.to_string()))
    }

    fn is_available(&self) -> bool {
        true
    }

    fn backend_name(&self) -> &'static str {
        "Linux Keyring (software)"
    }
}

// ---------------------------------------------------------------------------
// Key file management
// ---------------------------------------------------------------------------

/// Return the path to the AES key file: `~/.config/awsenc/storage.key`.
fn key_file_path() -> Result<PathBuf> {
    let home = dirs::home_dir()
        .ok_or_else(|| StorageError::KeyInitFailed("could not determine home directory".into()))?;
    let dir = home.join(".config").join("awsenc");
    Ok(dir.join("storage.key"))
}

/// Ensure `~/.config/awsenc/` exists with mode 0o700.
fn ensure_config_dir(path: &std::path::Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent).map_err(|e| {
                StorageError::KeyInitFailed(format!(
                    "failed to create config directory {}: {e}",
                    parent.display()
                ))
            })?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(|e| {
                    StorageError::KeyInitFailed(format!(
                        "failed to set permissions on {}: {e}",
                        parent.display()
                    ))
                })?;
            }
        }
    }
    Ok(())
}

/// Load the AES key from disk, or generate a new one if it doesn't exist.
fn load_or_generate_key() -> Result<[u8; KEY_SIZE]> {
    let path = key_file_path()?;

    if path.exists() {
        let data = fs::read(&path).map_err(|e| {
            StorageError::KeyInitFailed(format!("failed to read key file {}: {e}", path.display()))
        })?;

        if data.len() != KEY_SIZE {
            return Err(StorageError::KeyInitFailed(format!(
                "key file {} has invalid size: expected {KEY_SIZE}, got {}",
                path.display(),
                data.len()
            )));
        }

        let mut key = [0u8; KEY_SIZE];
        key.copy_from_slice(&data);
        debug!("loaded existing AES key from {}", path.display());
        Ok(key)
    } else {
        ensure_config_dir(&path)?;

        let mut key = [0u8; KEY_SIZE];
        rand::thread_rng().fill_bytes(&mut key);

        fs::write(&path, key).map_err(|e| {
            StorageError::KeyInitFailed(format!("failed to write key file {}: {e}", path.display()))
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).map_err(|e| {
                StorageError::KeyInitFailed(format!(
                    "failed to set permissions on {}: {e}",
                    path.display()
                ))
            })?;
        }

        debug!("generated new AES key at {}", path.display());
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_storage(dir: &std::path::Path) -> LinuxKeyringStorage {
        // Override the key file location for testing by creating the key directly.
        let key_path = dir.join("storage.key");
        let mut key = [0u8; KEY_SIZE];
        rand::thread_rng().fill_bytes(&mut key);
        fs::write(&key_path, key).unwrap();

        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        LinuxKeyringStorage { cipher }
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let storage = create_test_storage(dir.path());

        let plaintext = b"linux keyring test data";
        let ciphertext = storage.encrypt(plaintext).unwrap();
        let decrypted = storage.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_produces_different_ciphertexts() {
        let dir = tempfile::tempdir().unwrap();
        let storage = create_test_storage(dir.path());

        let plaintext = b"same data";
        let ct1 = storage.encrypt(plaintext).unwrap();
        let ct2 = storage.encrypt(plaintext).unwrap();
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn decrypt_too_short_fails() {
        let dir = tempfile::tempdir().unwrap();
        let storage = create_test_storage(dir.path());

        let result = storage.decrypt(&[0u8; 5]);
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_tampered_data_fails() {
        let dir = tempfile::tempdir().unwrap();
        let storage = create_test_storage(dir.path());

        let mut ciphertext = storage.encrypt(b"tamper test").unwrap();
        if let Some(byte) = ciphertext.get_mut(NONCE_SIZE + 1) {
            *byte ^= 0xff;
        }
        assert!(storage.decrypt(&ciphertext).is_err());
    }

    #[test]
    fn backend_name_is_correct() {
        let dir = tempfile::tempdir().unwrap();
        let storage = create_test_storage(dir.path());
        assert_eq!(storage.backend_name(), "Linux Keyring (software)");
    }

    #[test]
    fn is_available_returns_true() {
        let dir = tempfile::tempdir().unwrap();
        let storage = create_test_storage(dir.path());
        assert!(storage.is_available());
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let storage = create_test_storage(dir.path());

        let ciphertext = storage.encrypt(b"").unwrap();
        let decrypted = storage.decrypt(&ciphertext).unwrap();
        assert!(decrypted.is_empty());
    }
}
