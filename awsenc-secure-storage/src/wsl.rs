use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use base64::Engine;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::{Result, SecureStorage, StorageError};

/// Known locations for the TPM bridge executable.
const BRIDGE_PATHS: &[&str] = &[
    "/mnt/c/Program Files/awsenc/awsenc-tpm-bridge.exe",
    "/mnt/c/ProgramData/awsenc/awsenc-tpm-bridge.exe",
];

// ---------------------------------------------------------------------------
// JSON-RPC types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct BridgeRequest {
    method: String,
    params: BridgeParams,
}

#[derive(Debug, Serialize)]
struct BridgeParams {
    data: String,
    biometric: bool,
}

#[derive(Debug, Deserialize)]
struct BridgeResponse {
    result: Option<String>,
    error: Option<String>,
}

// ---------------------------------------------------------------------------
// WSL detection
// ---------------------------------------------------------------------------

/// Returns `true` if the current environment is Windows Subsystem for Linux.
pub fn is_wsl() -> bool {
    // Check the WSL_DISTRO_NAME environment variable first (fastest).
    if std::env::var("WSL_DISTRO_NAME").is_ok() {
        return true;
    }

    // Fall back to checking /proc/version for WSL indicators.
    if let Ok(version) = std::fs::read_to_string("/proc/version") {
        let lower = version.to_lowercase();
        if lower.contains("microsoft") || lower.contains("wsl") {
            return true;
        }
    }

    false
}

// ---------------------------------------------------------------------------
// WslBridgeStorage
// ---------------------------------------------------------------------------

/// Communicates with the Windows TPM 2.0 via a bridge executable.
///
/// The bridge (`awsenc-tpm-bridge.exe`) runs on the Windows side and exposes
/// TPM encrypt/decrypt operations over a JSON-RPC protocol on stdin/stdout.
pub struct WslBridgeStorage {
    bridge_path: PathBuf,
    biometric: bool,
}

impl WslBridgeStorage {
    /// Locate the bridge executable and create a new storage instance.
    pub fn new(biometric: bool) -> Result<Self> {
        let bridge_path = find_bridge_executable().ok_or_else(|| StorageError::NotAvailable)?;

        debug!("WSL TPM bridge found at {}", bridge_path.display());

        Ok(Self {
            bridge_path,
            biometric,
        })
    }

    /// Send a JSON-RPC request to the bridge and return the result.
    fn call_bridge(&self, method: &str, data: &[u8]) -> Result<Vec<u8>> {
        let encoded = base64::engine::general_purpose::STANDARD.encode(data);

        let request = BridgeRequest {
            method: method.to_owned(),
            params: BridgeParams {
                data: encoded,
                biometric: self.biometric,
            },
        };

        let request_json = serde_json::to_string(&request).map_err(|e| {
            StorageError::PlatformError(format!("failed to serialize bridge request: {e}"))
        })?;

        debug!("sending {} request to TPM bridge", method);

        let mut child = Command::new(&self.bridge_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                StorageError::PlatformError(format!(
                    "failed to spawn TPM bridge at {}: {e}",
                    self.bridge_path.display()
                ))
            })?;

        // Write request to stdin.
        if let Some(mut stdin) = child.stdin.take() {
            writeln!(stdin, "{request_json}").map_err(|e| {
                StorageError::PlatformError(format!("failed to write to bridge stdin: {e}"))
            })?;
            // Drop stdin to signal EOF.
        }

        // Read response from stdout.
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| StorageError::PlatformError("failed to capture bridge stdout".into()))?;

        let mut reader = BufReader::new(stdout);
        let mut response_line = String::new();
        reader.read_line(&mut response_line).map_err(|e| {
            StorageError::PlatformError(format!("failed to read bridge response: {e}"))
        })?;

        // Wait for the process to exit.
        let status = child.wait().map_err(|e| {
            StorageError::PlatformError(format!("failed to wait for bridge process: {e}"))
        })?;

        if !status.success() {
            return Err(StorageError::PlatformError(format!(
                "bridge process exited with status {status}"
            )));
        }

        let response: BridgeResponse = serde_json::from_str(response_line.trim()).map_err(|e| {
            StorageError::PlatformError(format!("failed to parse bridge response: {e}"))
        })?;

        if let Some(err) = response.error {
            return Err(match method {
                "encrypt" => StorageError::EncryptionFailed(err),
                "decrypt" => StorageError::DecryptionFailed(err),
                _ => StorageError::PlatformError(err),
            });
        }

        let result_b64 = response.result.ok_or_else(|| {
            StorageError::PlatformError("bridge response missing both result and error".into())
        })?;

        base64::engine::general_purpose::STANDARD
            .decode(&result_b64)
            .map_err(|e| {
                StorageError::PlatformError(format!("failed to decode bridge response: {e}"))
            })
    }
}

impl SecureStorage for WslBridgeStorage {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.call_bridge("encrypt", plaintext)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.call_bridge("decrypt", ciphertext)
    }

    fn is_available(&self) -> bool {
        self.bridge_path.exists()
    }

    fn backend_name(&self) -> &'static str {
        "TPM 2.0 (WSL Bridge)"
    }
}

/// Search known paths for the TPM bridge executable.
fn find_bridge_executable() -> Option<PathBuf> {
    for path_str in BRIDGE_PATHS {
        let path = Path::new(path_str);
        if path.exists() {
            return Some(path.to_path_buf());
        }
    }

    // Also check PATH in case it's installed elsewhere.
    if let Ok(output) = Command::new("which").arg("awsenc-tpm-bridge.exe").output() {
        if output.status.success() {
            let path_str = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            if !path_str.is_empty() {
                let path = PathBuf::from(&path_str);
                if path.exists() {
                    return Some(path);
                }
            }
        }
    }

    warn!("TPM bridge executable not found in any known location");
    None
}

#[cfg(test)]
mod tests {
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

    #[test]
    fn bridge_request_serialization() {
        let request = BridgeRequest {
            method: "encrypt".to_owned(),
            params: BridgeParams {
                data: "aGVsbG8=".to_owned(),
                biometric: false,
            },
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"method\":\"encrypt\""));
        assert!(json.contains("\"data\":\"aGVsbG8=\""));
        assert!(json.contains("\"biometric\":false"));
    }

    #[test]
    fn bridge_response_deserialization_success() {
        let json = r#"{"result": "ZW5jcnlwdGVk", "error": null}"#;
        let resp: BridgeResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.result.as_deref(), Some("ZW5jcnlwdGVk"));
        assert!(resp.error.is_none());
    }

    #[test]
    fn bridge_response_deserialization_error() {
        let json = r#"{"result": null, "error": "TPM not available"}"#;
        let resp: BridgeResponse = serde_json::from_str(json).unwrap();
        assert!(resp.result.is_none());
        assert_eq!(resp.error.as_deref(), Some("TPM not available"));
    }

    #[test]
    fn bridge_response_deserialization_missing_fields() {
        // The bridge may omit null fields.
        let json = r#"{"result": "ZGF0YQ=="}"#;
        let resp: BridgeResponse = serde_json::from_str(json).unwrap();
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
    }
}
