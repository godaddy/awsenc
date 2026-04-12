// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! WSL bridge storage using libenclaveapp's bridge client.
//!
//! Communicates with the Windows TPM bridge executable over JSON-RPC
//! (stdin/stdout). Uses `enclaveapp-bridge` for protocol types and
//! the client helper, with `enclaveapp-wsl` for WSL detection.

use std::path::PathBuf;

use tracing::{debug, warn};

use crate::{Result, SecureStorage, StorageError};

/// Application name for bridge discovery and key namespacing.
const APP_NAME: &str = "awsenc";

/// Additional legacy paths for the bridge executable.
const LEGACY_BRIDGE_PATHS: &[&str] = &[
    "/mnt/c/Program Files/awsenc/awsenc-tpm-bridge.exe",
    "/mnt/c/ProgramData/awsenc/awsenc-tpm-bridge.exe",
];

// ---------------------------------------------------------------------------
// WSL detection
// ---------------------------------------------------------------------------

/// Returns `true` if the current environment is Windows Subsystem for Linux.
pub fn is_wsl() -> bool {
    enclaveapp_wsl::is_wsl()
}

// ---------------------------------------------------------------------------
// WslBridgeStorage
// ---------------------------------------------------------------------------

/// Communicates with the Windows TPM 2.0 via a bridge executable.
///
/// The bridge runs on the Windows side and exposes TPM encrypt/decrypt
/// operations over a JSON-RPC protocol on stdin/stdout.
#[derive(Debug)]
pub struct WslBridgeStorage {
    bridge_path: PathBuf,
    biometric: bool,
}

impl WslBridgeStorage {
    /// Locate the bridge executable and create a new storage instance.
    pub fn new(biometric: bool) -> Result<Self> {
        let bridge_path = find_bridge_executable().ok_or(StorageError::NotAvailable)?;

        debug!("WSL TPM bridge found at {}", bridge_path.display());

        Ok(Self {
            bridge_path,
            biometric,
        })
    }
}

impl SecureStorage for WslBridgeStorage {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        enclaveapp_bridge::bridge_encrypt(&self.bridge_path, APP_NAME, plaintext, self.biometric)
            .map_err(|e| StorageError::EncryptionFailed(e.to_string()))
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        enclaveapp_bridge::bridge_decrypt(&self.bridge_path, APP_NAME, ciphertext, self.biometric)
            .map_err(|e| StorageError::DecryptionFailed(e.to_string()))
    }

    fn is_available(&self) -> bool {
        self.bridge_path.exists()
    }

    fn backend_name(&self) -> &'static str {
        "TPM 2.0 (WSL Bridge)"
    }
}

/// Search for the bridge executable using enclaveapp-bridge's finder,
/// then fall back to legacy awsenc-specific paths.
fn find_bridge_executable() -> Option<PathBuf> {
    // Try the libenclaveapp standard discovery first.
    if let Some(path) = enclaveapp_bridge::find_bridge(APP_NAME) {
        return Some(path);
    }

    // Fall back to legacy awsenc-specific paths.
    for path_str in LEGACY_BRIDGE_PATHS {
        let path = std::path::Path::new(path_str);
        if path.exists() {
            return Some(path.to_path_buf());
        }
    }

    warn!("TPM bridge executable not found in any known location");
    None
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn is_wsl_returns_bool() {
        // On a real Linux machine this returns true or false.
        // On macOS (where tests typically run) it should return false.
        let _result = is_wsl();
    }

    #[test]
    fn find_bridge_executable_does_not_panic() {
        // Should return None on most development machines.
        let _path = find_bridge_executable();
    }
}
