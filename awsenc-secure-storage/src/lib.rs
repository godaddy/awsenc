use thiserror::Error;

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("hardware security module not available")]
    NotAvailable,
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("key initialization failed: {0}")]
    KeyInitFailed(String),
    #[error("key not found")]
    KeyNotFound,
    #[error("platform error: {0}")]
    PlatformError(String),
}

pub type Result<T> = std::result::Result<T, StorageError>;

/// Hardware-backed secure storage trait.
/// Implementations encrypt/decrypt arbitrary byte slices using
/// hardware-bound keys (Secure Enclave, TPM, etc.).
pub trait SecureStorage: Send + Sync {
    /// Encrypt plaintext bytes. Returns ciphertext that can only be
    /// decrypted on this device by the same hardware key.
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Decrypt ciphertext previously encrypted by this storage.
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;

    /// Check if the hardware backend is available on this system.
    fn is_available(&self) -> bool;

    /// A human-readable name for this backend (e.g., "Secure Enclave", "TPM 2.0").
    fn backend_name(&self) -> &'static str;
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(feature = "mock")]
pub mod mock;
#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "linux")]
mod wsl;

/// Create the appropriate `SecureStorage` implementation for the current platform.
///
/// On macOS, returns a Secure Enclave-backed implementation.
/// On Linux under WSL, returns a TPM bridge client.
/// On native Linux, returns a file-based AES-GCM implementation.
pub fn create_platform_storage(biometric: bool) -> Result<Box<dyn SecureStorage>> {
    #[cfg(target_os = "macos")]
    {
        let storage = macos::MacosSecureEnclaveStorage::new(biometric)?;
        Ok(Box::new(storage))
    }

    #[cfg(target_os = "linux")]
    {
        if wsl::is_wsl() {
            let storage = wsl::WslBridgeStorage::new(biometric)?;
            Ok(Box::new(storage))
        } else {
            let _ = biometric; // Linux keyring doesn't support biometric
            let storage = linux::LinuxKeyringStorage::new()?;
            Ok(Box::new(storage))
        }
    }

    #[cfg(target_os = "windows")]
    {
        let storage = windows::WindowsTpmStorage::new(biometric)?;
        Ok(Box::new(storage))
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = biometric;
        Err(StorageError::NotAvailable)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn storage_error_display() {
        let err = StorageError::NotAvailable;
        assert_eq!(err.to_string(), "hardware security module not available");

        let err = StorageError::EncryptionFailed("bad key".into());
        assert_eq!(err.to_string(), "encryption failed: bad key");

        let err = StorageError::DecryptionFailed("corrupt data".into());
        assert_eq!(err.to_string(), "decryption failed: corrupt data");

        let err = StorageError::KeyInitFailed("no hardware".into());
        assert_eq!(err.to_string(), "key initialization failed: no hardware");

        let err = StorageError::KeyNotFound;
        assert_eq!(err.to_string(), "key not found");

        let err = StorageError::PlatformError("oops".into());
        assert_eq!(err.to_string(), "platform error: oops");
    }

    #[test]
    fn create_platform_storage_returns_backend() {
        // On macOS this should succeed (Secure Enclave may not be available in CI),
        // on other platforms we just verify it doesn't panic.
        let result = create_platform_storage(false);
        // We can't assert success because CI may lack hardware, but it shouldn't panic.
        if let Ok(storage) = result {
            assert!(!storage.backend_name().is_empty());
        }
        // Err is expected on systems without hardware support or unsupported platforms.
    }
}
