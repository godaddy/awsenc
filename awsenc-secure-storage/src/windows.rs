// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Windows TPM 2.0 storage backed by libenclaveapp's CNG ECIES.

use enclaveapp_core::traits::{EnclaveEncryptor, EnclaveKeyManager};
use enclaveapp_core::types::{AccessPolicy, KeyType};
use enclaveapp_windows::TpmEncryptor;
use tracing::debug;

use crate::{Result, SecureStorage, StorageError};

/// Application name used to namespace keys in libenclaveapp.
const APP_NAME: &str = "awsenc";

/// Key label used for the credential encryption key.
const KEY_LABEL: &str = "cache-key";

/// Windows TPM 2.0-backed storage using CNG ECIES.
///
/// Wraps libenclaveapp's `TpmEncryptor`, binding a fixed key label
/// so the rest of awsenc does not need to manage label selection.
pub struct WindowsTpmStorage {
    encryptor: TpmEncryptor,
    biometric: bool,
}

impl std::fmt::Debug for WindowsTpmStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WindowsTpmStorage")
            .field("encryptor", &"<TpmEncryptor>")
            .field("biometric", &self.biometric)
            .finish()
    }
}

impl WindowsTpmStorage {
    /// Create a new TPM storage, loading or generating the key pair.
    pub fn new(biometric: bool) -> Result<Self> {
        let encryptor = TpmEncryptor::new(APP_NAME);

        if !encryptor.is_available() {
            return Err(StorageError::NotAvailable);
        }

        // Ensure the key exists; generate if missing.
        if encryptor.public_key(KEY_LABEL).is_err() {
            debug!("no existing TPM key found, generating new key pair");
            let policy = if biometric {
                AccessPolicy::BiometricOnly
            } else {
                AccessPolicy::None
            };
            encryptor
                .generate(KEY_LABEL, KeyType::Encryption, policy)
                .map_err(|e| StorageError::KeyInitFailed(e.to_string()))?;
        }

        debug!("TPM key pair ready (biometric={})", biometric);

        Ok(Self {
            encryptor,
            biometric,
        })
    }
}

impl SecureStorage for WindowsTpmStorage {
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
        self.encryptor.is_available()
    }

    fn backend_name(&self) -> &'static str {
        if self.biometric {
            "TPM 2.0 (biometric)"
        } else {
            "TPM 2.0"
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::print_stdout)]

    use super::*;

    #[test]
    fn tpm_availability_check() {
        let encryptor = TpmEncryptor::new(APP_NAME);
        let available = encryptor.is_available();
        println!("TPM available: {available}");
    }

    #[test]
    fn encrypt_decrypt_roundtrip_if_hardware_available() {
        if std::env::var("AWSENC_TEST_TPM").is_err() {
            println!("skipping: set AWSENC_TEST_TPM=1 to run hardware tests");
            return;
        }

        let storage = WindowsTpmStorage::new(false).expect("TPM should be available for this test");

        let plaintext = b"test credential data for TPM";
        let ciphertext = storage.encrypt(plaintext).expect("encryption failed");
        assert_ne!(&ciphertext[..], plaintext);

        let decrypted = storage.decrypt(&ciphertext).expect("decryption failed");
        assert_eq!(&decrypted[..], plaintext);
    }
}
