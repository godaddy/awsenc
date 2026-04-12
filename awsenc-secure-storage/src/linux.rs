// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Software-only Linux storage backed by libenclaveapp's `SoftwareEncryptor`.
//!
//! Uses ECIES (P-256 ECDH + AES-256-GCM) with private keys stored on disk,
//! optionally encrypted by a keyring-stored KEK. This replaces the earlier
//! hand-rolled AES-256-GCM implementation with a shared backend from
//! libenclaveapp.

use enclaveapp_core::traits::{EnclaveEncryptor, EnclaveKeyManager};
use enclaveapp_core::types::{AccessPolicy, KeyType};
use enclaveapp_software::SoftwareEncryptor;
use tracing::debug;

use crate::{Result, SecureStorage, StorageError};

/// Application name used to namespace keys in libenclaveapp.
const APP_NAME: &str = "awsenc";

/// Key label used for the credential encryption key.
const KEY_LABEL: &str = "cache-key";

/// Software-only Linux storage using libenclaveapp's `SoftwareEncryptor`.
///
/// Wraps `SoftwareEncryptor` with the same fixed key label used by the
/// macOS Secure Enclave backend so the rest of awsenc is backend-agnostic.
pub struct LinuxKeyringStorage {
    encryptor: SoftwareEncryptor,
}

impl std::fmt::Debug for LinuxKeyringStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinuxKeyringStorage")
            .field("encryptor", &"<SoftwareEncryptor>")
            .finish()
    }
}

impl LinuxKeyringStorage {
    /// Create a new Linux software storage, loading or generating the key pair.
    ///
    /// Prints a one-time warning to stderr about software-only storage.
    pub fn new() -> Result<Self> {
        let encryptor = SoftwareEncryptor::new(APP_NAME);

        // Ensure the key exists; generate if missing.
        if encryptor.public_key(KEY_LABEL).is_err() {
            debug!("no existing software key found, generating new key pair");
            encryptor
                .generate(KEY_LABEL, KeyType::Encryption, AccessPolicy::None)
                .map_err(|e| StorageError::KeyInitFailed(e.to_string()))?;
        }

        debug!("Linux software storage initialized");
        Ok(Self { encryptor })
    }
}

impl SecureStorage for LinuxKeyringStorage {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.encryptor
            .encrypt(KEY_LABEL, plaintext)
            .map_err(|e| StorageError::EncryptionFailed(e.to_string()))
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.encryptor
            .decrypt(KEY_LABEL, ciphertext)
            .map_err(|e| StorageError::DecryptionFailed(e.to_string()))
    }

    fn is_available(&self) -> bool {
        true
    }

    fn backend_name(&self) -> &'static str {
        "Linux (software)"
    }
}
