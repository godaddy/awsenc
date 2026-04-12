use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use rand::RngCore;

use crate::{Result, SecureStorage, StorageError};

/// Nonce size for AES-256-GCM (96 bits).
const NONCE_SIZE: usize = 12;

/// Mock secure storage for testing. Uses AES-256-GCM with a random
/// in-memory key. Provides no hardware backing; suitable only for
/// tests and development.
pub struct MockStorage {
    cipher: Aes256Gcm,
}

impl std::fmt::Debug for MockStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockStorage")
            .field("cipher", &"<Aes256Gcm>")
            .finish()
    }
}

impl MockStorage {
    /// Create a new mock storage with a randomly generated AES-256 key.
    pub fn new() -> Self {
        let mut key_bytes = [0_u8; 32];
        rand::thread_rng().fill_bytes(&mut key_bytes);
        let cipher = Aes256Gcm::new_from_slice(&key_bytes)
            .expect("32-byte key is always valid for AES-256-GCM");
        Self { cipher }
    }
}

impl Default for MockStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl SecureStorage for MockStorage {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce_bytes = [0_u8; NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| StorageError::EncryptionFailed(e.to_string()))?;

        // Prepend nonce to ciphertext: [nonce (12 bytes) | ciphertext + tag]
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
        "Mock (AES-GCM)"
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let storage = MockStorage::new();
        let plaintext = b"hello, secure world!";

        let ciphertext = storage.encrypt(plaintext).unwrap();
        assert_ne!(ciphertext, plaintext);
        assert!(ciphertext.len() > plaintext.len());

        let decrypted = storage.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_produces_different_ciphertexts() {
        let storage = MockStorage::new();
        let plaintext = b"same input";

        let ct1 = storage.encrypt(plaintext).unwrap();
        let ct2 = storage.encrypt(plaintext).unwrap();
        // Random nonces mean different ciphertexts each time.
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn decrypt_empty_input_fails() {
        let storage = MockStorage::new();
        let result = storage.decrypt(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_short_input_fails() {
        let storage = MockStorage::new();
        let result = storage.decrypt(&[0_u8; 5]);
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_tampered_ciphertext_fails() {
        let storage = MockStorage::new();
        let plaintext = b"sensitive data";

        let mut ciphertext = storage.encrypt(plaintext).unwrap();
        // Tamper with the encrypted portion (after the nonce).
        if let Some(byte) = ciphertext.get_mut(NONCE_SIZE + 1) {
            *byte ^= 0xff;
        }
        let result = storage.decrypt(&ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let storage1 = MockStorage::new();
        let storage2 = MockStorage::new();
        let plaintext = b"key-specific data";

        let ciphertext = storage1.encrypt(plaintext).unwrap();
        let result = storage2.decrypt(&ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn encrypt_empty_plaintext() {
        let storage = MockStorage::new();
        let ciphertext = storage.encrypt(b"").unwrap();
        let decrypted = storage.decrypt(&ciphertext).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn encrypt_large_plaintext() {
        let storage = MockStorage::new();
        let plaintext = vec![0xAB_u8; 1_000_000];
        let ciphertext = storage.encrypt(&plaintext).unwrap();
        let decrypted = storage.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn is_available_returns_true() {
        let storage = MockStorage::new();
        assert!(storage.is_available());
    }

    #[test]
    fn backend_name_is_correct() {
        let storage = MockStorage::new();
        assert_eq!(storage.backend_name(), "Mock (AES-GCM)");
    }

    #[test]
    fn default_impl_works() {
        let storage = MockStorage::default();
        let plaintext = b"default test";
        let ciphertext = storage.encrypt(plaintext).unwrap();
        let decrypted = storage.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_decrypt_various_sizes() {
        let storage = MockStorage::new();
        for size in [0, 1, 100, 10_000] {
            let plaintext = vec![0xAA_u8; size];
            let ciphertext = storage.encrypt(&plaintext).unwrap();
            let decrypted = storage.decrypt(&ciphertext).unwrap();
            assert_eq!(decrypted, plaintext, "roundtrip failed for size {size}");
        }
    }

    #[test]
    fn encrypt_output_differs_from_plaintext() {
        let storage = MockStorage::new();
        let plaintext = b"this should not appear in ciphertext verbatim";
        let ciphertext = storage.encrypt(plaintext).unwrap();
        // The nonce prefix and AES-GCM encryption ensure ciphertext differs
        assert_ne!(&ciphertext[..], &plaintext[..]);
        // Also verify ciphertext is longer (nonce + tag overhead)
        assert!(ciphertext.len() > plaintext.len());
    }

    #[test]
    fn decrypt_garbage_data_returns_error() {
        let storage = MockStorage::new();
        // 20 bytes of garbage — valid nonce length but bogus ciphertext
        let garbage = vec![0xFF_u8; 20];
        let result = storage.decrypt(&garbage);
        assert!(result.is_err(), "decrypting garbage should fail");
    }

    #[test]
    fn decrypt_nonce_only_returns_error() {
        let storage = MockStorage::new();
        // Exactly NONCE_SIZE bytes — empty ciphertext after nonce
        let nonce_only = vec![0x00_u8; NONCE_SIZE];
        let result = storage.decrypt(&nonce_only);
        assert!(result.is_err(), "decrypting nonce-only data should fail");
    }
}
