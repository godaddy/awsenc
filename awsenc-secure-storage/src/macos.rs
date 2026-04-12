// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! macOS Secure Enclave storage backed by libenclaveapp's CryptoKit ECIES.

use enclaveapp_apple::SecureEnclaveEncryptor;
use enclaveapp_core::traits::{EnclaveEncryptor, EnclaveKeyManager};
use enclaveapp_core::types::{AccessPolicy, KeyType};
use tracing::debug;

use crate::{Result, SecureStorage, StorageError};

/// Application name used to namespace keys in libenclaveapp.
const APP_NAME: &str = "awsenc";

/// Key label used for the credential encryption key.
const KEY_LABEL: &str = "cache-key";

/// macOS Secure Enclave-backed storage using CryptoKit ECIES.
///
/// Wraps libenclaveapp's `SecureEnclaveEncryptor`, binding a fixed key label
/// so the rest of awsenc does not need to manage label selection.
pub struct MacosSecureEnclaveStorage {
    encryptor: SecureEnclaveEncryptor,
    biometric: bool,
}

impl std::fmt::Debug for MacosSecureEnclaveStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MacosSecureEnclaveStorage")
            .field("encryptor", &"<SecureEnclaveEncryptor>")
            .field("biometric", &self.biometric)
            .finish()
    }
}

impl MacosSecureEnclaveStorage {
    /// Create a new Secure Enclave storage, loading or generating the key pair.
    pub fn new(biometric: bool) -> Result<Self> {
        let encryptor = SecureEnclaveEncryptor::new(APP_NAME);

        if !encryptor.is_available() {
            return Err(StorageError::NotAvailable);
        }

        // Ensure the key exists; generate if missing.
        if encryptor.public_key(KEY_LABEL).is_err() {
            debug!("no existing Secure Enclave key found, generating new key pair");
            let policy = if biometric {
                AccessPolicy::BiometricOnly
            } else {
                AccessPolicy::None
            };
            encryptor
                .generate(KEY_LABEL, KeyType::Encryption, policy)
                .map_err(|e| StorageError::KeyInitFailed(e.to_string()))?;
        }

        debug!("Secure Enclave key pair ready (biometric={})", biometric);

        Ok(Self {
            encryptor,
            biometric,
        })
    }
}

impl SecureStorage for MacosSecureEnclaveStorage {
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
            "Secure Enclave (biometric)"
        } else {
            "Secure Enclave"
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::print_stdout)]

    use super::*;

    #[test]
    fn secure_enclave_availability_check() {
        let encryptor = SecureEnclaveEncryptor::new(APP_NAME);
        let available = encryptor.is_available();
        println!("Secure Enclave available: {available}");
    }

    // Integration tests that require actual Secure Enclave hardware
    // are gated behind the AWSENC_TEST_SECURE_ENCLAVE environment variable.
    #[test]
    fn encrypt_decrypt_roundtrip_if_hardware_available() {
        if std::env::var("AWSENC_TEST_SECURE_ENCLAVE").is_err() {
            println!("skipping: set AWSENC_TEST_SECURE_ENCLAVE=1 to run hardware tests");
            return;
        }

        let storage = MacosSecureEnclaveStorage::new(false)
            .expect("Secure Enclave should be available for this test");

        let plaintext = b"test credential data for Secure Enclave";
        let ciphertext = storage.encrypt(plaintext).expect("encryption failed");
        assert_ne!(&ciphertext[..], plaintext);

        let decrypted = storage.decrypt(&ciphertext).expect("decryption failed");
        assert_eq!(&decrypted[..], plaintext);
    }
}
