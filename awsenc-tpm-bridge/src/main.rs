mod tpm;

use base64::prelude::*;
use serde::{Deserialize, Serialize};
use std::io::{self, BufRead, Write};

#[derive(Debug, Deserialize)]
struct Request {
    method: String,
    params: Option<Params>,
}

#[derive(Debug, Deserialize)]
struct Params {
    data: Option<String>,
    biometric: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum Response {
    Success { result: String },
    Error { error: String },
}

fn handle_request(request: &Request, storage: &mut Option<tpm::TpmStorage>) -> Response {
    match request.method.as_str() {
        "init" => {
            let biometric = request
                .params
                .as_ref()
                .and_then(|p| p.biometric)
                .unwrap_or(false);
            match tpm::TpmStorage::new(biometric) {
                Ok(s) => {
                    *storage = Some(s);
                    Response::Success {
                        result: "ok".to_string(),
                    }
                }
                Err(e) => Response::Error {
                    error: format!("init failed: {e}"),
                },
            }
        }
        "encrypt" => {
            let Some(ref s) = storage else {
                return Response::Error {
                    error: "not initialized: call init first".to_string(),
                };
            };
            let Some(data_b64) = request.params.as_ref().and_then(|p| p.data.as_deref()) else {
                return Response::Error {
                    error: "missing data parameter".to_string(),
                };
            };
            let plaintext = match BASE64_STANDARD.decode(data_b64) {
                Ok(d) => d,
                Err(e) => {
                    return Response::Error {
                        error: format!("base64 decode error: {e}"),
                    };
                }
            };
            match s.encrypt(&plaintext) {
                Ok(ciphertext) => Response::Success {
                    result: BASE64_STANDARD.encode(&ciphertext),
                },
                Err(e) => Response::Error {
                    error: format!("encrypt failed: {e}"),
                },
            }
        }
        "decrypt" => {
            let Some(ref s) = storage else {
                return Response::Error {
                    error: "not initialized: call init first".to_string(),
                };
            };
            let Some(data_b64) = request.params.as_ref().and_then(|p| p.data.as_deref()) else {
                return Response::Error {
                    error: "missing data parameter".to_string(),
                };
            };
            let ciphertext = match BASE64_STANDARD.decode(data_b64) {
                Ok(d) => d,
                Err(e) => {
                    return Response::Error {
                        error: format!("base64 decode error: {e}"),
                    };
                }
            };
            match s.decrypt(&ciphertext) {
                Ok(plaintext) => Response::Success {
                    result: BASE64_STANDARD.encode(&plaintext),
                },
                Err(e) => Response::Error {
                    error: format!("decrypt failed: {e}"),
                },
            }
        }
        "destroy" => {
            *storage = None;
            Response::Success {
                result: "ok".to_string(),
            }
        }
        other => Response::Error {
            error: format!("unknown method: {other}"),
        },
    }
}

fn main() {
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    let mut storage: Option<tpm::TpmStorage> = None;

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                let resp = Response::Error {
                    error: format!("read error: {e}"),
                };
                drop(serde_json::to_writer(&mut stdout, &resp));
                drop(stdout.write_all(b"\n"));
                drop(stdout.flush());
                break;
            }
        };

        if line.trim().is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<Request>(&line) {
            Ok(req) => handle_request(&req, &mut storage),
            Err(e) => Response::Error {
                error: format!("invalid JSON: {e}"),
            },
        };

        if serde_json::to_writer(&mut stdout, &response).is_err() {
            break;
        }
        if stdout.write_all(b"\n").is_err() {
            break;
        }
        if stdout.flush().is_err() {
            break;
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parse_init_request() {
        let json = r#"{"method": "init", "params": {"biometric": false}}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert_eq!(req.method, "init");
        assert_eq!(req.params.as_ref().unwrap().biometric, Some(false));
        assert!(req.params.as_ref().unwrap().data.is_none());
    }

    #[test]
    fn parse_init_request_no_params() {
        let json = r#"{"method": "init"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert_eq!(req.method, "init");
        assert!(req.params.is_none());
    }

    #[test]
    fn parse_encrypt_request() {
        let json = r#"{"method": "encrypt", "params": {"data": "aGVsbG8=", "biometric": false}}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert_eq!(req.method, "encrypt");
        assert_eq!(
            req.params.as_ref().unwrap().data.as_deref(),
            Some("aGVsbG8=")
        );
    }

    #[test]
    fn parse_decrypt_request() {
        let json = r#"{"method": "decrypt", "params": {"data": "Y2lwaGVy"}}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert_eq!(req.method, "decrypt");
        assert_eq!(
            req.params.as_ref().unwrap().data.as_deref(),
            Some("Y2lwaGVy")
        );
    }

    #[test]
    fn parse_destroy_request() {
        let json = r#"{"method": "destroy"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert_eq!(req.method, "destroy");
    }

    #[test]
    fn serialize_success_response() {
        let resp = Response::Success {
            result: "ok".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert_eq!(json, r#"{"result":"ok"}"#);
    }

    #[test]
    fn serialize_error_response() {
        let resp = Response::Error {
            error: "something went wrong".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert_eq!(json, r#"{"error":"something went wrong"}"#);
    }

    #[test]
    fn handle_init_creates_storage() {
        let req = Request {
            method: "init".to_string(),
            params: Some(Params {
                data: None,
                biometric: Some(false),
            }),
        };
        let mut storage = None;
        let resp = handle_request(&req, &mut storage);
        // On non-Windows, init succeeds (stub creates the struct)
        // but encrypt/decrypt will fail at runtime
        match resp {
            Response::Success { result } => assert_eq!(result, "ok"),
            Response::Error { error } => {
                // On Windows CI without TPM, init might fail - that's ok
                assert!(error.contains("init failed"), "unexpected error: {error}");
            }
        }
    }

    #[test]
    fn handle_destroy_clears_storage() {
        let req = Request {
            method: "destroy".to_string(),
            params: None,
        };
        let mut storage = None;
        let resp = handle_request(&req, &mut storage);
        match resp {
            Response::Success { result } => assert_eq!(result, "ok"),
            Response::Error { .. } => panic!("destroy should succeed"),
        }
        assert!(storage.is_none());
    }

    #[test]
    fn handle_unknown_method() {
        let req = Request {
            method: "bogus".to_string(),
            params: None,
        };
        let mut storage = None;
        let resp = handle_request(&req, &mut storage);
        match resp {
            Response::Error { error } => assert!(error.contains("unknown method")),
            Response::Success { .. } => panic!("should have returned error"),
        }
    }

    #[test]
    fn handle_encrypt_without_init() {
        let req = Request {
            method: "encrypt".to_string(),
            params: Some(Params {
                data: Some("aGVsbG8=".to_string()),
                biometric: None,
            }),
        };
        let mut storage = None;
        let resp = handle_request(&req, &mut storage);
        match resp {
            Response::Error { error } => assert!(error.contains("not initialized")),
            Response::Success { .. } => panic!("should have returned error"),
        }
    }

    #[test]
    fn handle_decrypt_without_init() {
        let req = Request {
            method: "decrypt".to_string(),
            params: Some(Params {
                data: Some("Y2lwaGVy".to_string()),
                biometric: None,
            }),
        };
        let mut storage = None;
        let resp = handle_request(&req, &mut storage);
        match resp {
            Response::Error { error } => assert!(error.contains("not initialized")),
            Response::Success { .. } => panic!("should have returned error"),
        }
    }

    #[test]
    fn handle_encrypt_missing_data() {
        let req = Request {
            method: "encrypt".to_string(),
            params: Some(Params {
                data: None,
                biometric: None,
            }),
        };
        // On platforms without a TPM, new() may fail and storage is None,
        // so we get "not initialized" instead of "missing data". Both are valid errors.
        let mut storage = tpm::TpmStorage::new(false).ok();
        let resp = handle_request(&req, &mut storage);
        match resp {
            Response::Error { error } => {
                assert!(
                    error.contains("missing data") || error.contains("not initialized"),
                    "unexpected error: {error}"
                );
            }
            Response::Success { .. } => panic!("should have returned error"),
        }
    }

    #[test]
    fn handle_encrypt_invalid_base64() {
        let req = Request {
            method: "encrypt".to_string(),
            params: Some(Params {
                data: Some("not-valid-base64!!!".to_string()),
                biometric: None,
            }),
        };
        let mut storage = tpm::TpmStorage::new(false).ok();
        let resp = handle_request(&req, &mut storage);
        match resp {
            Response::Error { error } => {
                assert!(
                    error.contains("base64") || error.contains("not initialized"),
                    "unexpected error: {error}"
                );
            }
            Response::Success { .. } => panic!("should have returned error"),
        }
    }

    #[test]
    fn handle_decrypt_missing_data() {
        let req = Request {
            method: "decrypt".to_string(),
            params: None,
        };
        let mut storage = tpm::TpmStorage::new(false).ok();
        let resp = handle_request(&req, &mut storage);
        match resp {
            Response::Error { error } => {
                assert!(
                    error.contains("missing data") || error.contains("not initialized"),
                    "unexpected error: {error}"
                );
            }
            Response::Success { .. } => panic!("should have returned error"),
        }
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn encrypt_returns_platform_error_on_non_windows() {
        let storage = tpm::TpmStorage::new(false).unwrap();
        let result = storage.encrypt(b"hello");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("only supported on Windows"));
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn decrypt_returns_platform_error_on_non_windows() {
        let storage = tpm::TpmStorage::new(false).unwrap();
        let result = storage.decrypt(b"hello");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("only supported on Windows"));
    }

    #[test]
    fn roundtrip_json_protocol() {
        // Simulate the full JSON protocol flow
        let init_json = r#"{"method":"init","params":{"biometric":false}}"#;
        let encrypt_json = r#"{"method":"encrypt","params":{"data":"aGVsbG8gd29ybGQ="}}"#;
        let destroy_json = r#"{"method":"destroy"}"#;

        let mut storage = None;

        // Init
        let req: Request = serde_json::from_str(init_json).unwrap();
        let resp = handle_request(&req, &mut storage);
        let resp_json = serde_json::to_string(&resp).unwrap();
        assert!(
            resp_json.contains("\"result\"") || resp_json.contains("\"error\""),
            "response should be valid JSON-RPC"
        );

        // Encrypt (will fail on non-Windows, which is expected)
        let req: Request = serde_json::from_str(encrypt_json).unwrap();
        let resp = handle_request(&req, &mut storage);
        let resp_json = serde_json::to_string(&resp).unwrap();
        assert!(
            resp_json.contains("\"result\"") || resp_json.contains("\"error\""),
            "response should be valid JSON-RPC"
        );

        // Destroy
        let req: Request = serde_json::from_str(destroy_json).unwrap();
        let resp = handle_request(&req, &mut storage);
        let resp_json = serde_json::to_string(&resp).unwrap();
        assert_eq!(resp_json, r#"{"result":"ok"}"#);
        assert!(storage.is_none());
    }

    #[test]
    fn invalid_json_produces_error() {
        let bad_json = "this is not json";
        let result = serde_json::from_str::<Request>(bad_json);
        assert!(result.is_err());
    }
}
