// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! TPM 2.0 storage operations via libenclaveapp.
//!
//! On Windows, this uses `enclaveapp-windows::TpmEncryptor` to perform
//! hardware-backed ECIES encryption via the Windows CNG/NCrypt APIs.
//!
//! On non-Windows platforms, all operations return an error at runtime.

#[cfg(target_os = "windows")]
mod platform {
    use enclaveapp_core::traits::{EnclaveEncryptor, EnclaveKeyManager};
    use enclaveapp_core::types::{AccessPolicy, KeyType};
    use enclaveapp_windows::TpmEncryptor;

    pub struct TpmStorage {
        encryptor: TpmEncryptor,
        key_label: String,
    }

    impl TpmStorage {
        pub fn new(
            app_name: &str,
            key_label: &str,
            access_policy: AccessPolicy,
        ) -> Result<Self, String> {
            let encryptor = TpmEncryptor::new(app_name);

            if !encryptor.is_available() {
                return Err("TPM not available".to_string());
            }

            // Ensure the key exists; generate if missing.
            if encryptor.public_key(key_label).is_err() {
                encryptor
                    .generate(key_label, KeyType::Encryption, access_policy)
                    .map_err(|e| format!("key generation failed: {e}"))?;
            }

            Ok(Self {
                encryptor,
                key_label: key_label.to_owned(),
            })
        }

        pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
            self.encryptor
                .encrypt(&self.key_label, plaintext)
                .map_err(|e| e.to_string())
        }

        pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
            self.encryptor
                .decrypt(&self.key_label, ciphertext)
                .map_err(|e| e.to_string())
        }

        pub fn destroy(&self) -> Result<(), String> {
            self.encryptor
                .delete_key(&self.key_label)
                .map_err(|e| e.to_string())
        }
    }
}

#[cfg(not(target_os = "windows"))]
mod platform {
    pub struct TpmStorage {
        _app_name: String,
        _key_label: String,
    }

    impl TpmStorage {
        #[allow(clippy::unnecessary_wraps)]
        pub fn new(
            app_name: &str,
            key_label: &str,
            _access_policy: enclaveapp_core::AccessPolicy,
        ) -> Result<Self, String> {
            Ok(Self {
                _app_name: app_name.to_owned(),
                _key_label: key_label.to_owned(),
            })
        }

        #[allow(clippy::unused_self)]
        pub fn encrypt(&self, _plaintext: &[u8]) -> Result<Vec<u8>, String> {
            Err("TPM bridge is only supported on Windows".to_string())
        }

        #[allow(clippy::unused_self)]
        pub fn decrypt(&self, _ciphertext: &[u8]) -> Result<Vec<u8>, String> {
            Err("TPM bridge is only supported on Windows".to_string())
        }

        #[allow(clippy::unused_self)]
        pub fn destroy(&self) -> Result<(), String> {
            Err("TPM bridge is only supported on Windows".to_string())
        }
    }
}

pub use platform::TpmStorage;
