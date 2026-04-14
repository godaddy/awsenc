# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in awsenc, report it privately.

**Do not open a public GitHub issue for security vulnerabilities.**

Email: Report via GitHub's private vulnerability reporting feature on the
[awsenc repository](https://github.com/godaddy/awsenc/security/advisories/new),
or contact the maintainer directly.

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if you have one)

You will receive an acknowledgment within 72 hours. A fix will be developed
and released as quickly as possible, with credit given to the reporter
(unless anonymity is requested).

## Supported Versions

| Version | Supported |
|---|---|
| 0.4.x | Yes |

Only the latest release receives security fixes.

## Security Model Summary

awsenc encrypts AWS session credentials at rest using hardware-backed keys:

- **Credentials are encrypted with ECIES** using a P-256 key pair generated
  in the Secure Enclave (macOS), TPM 2.0 (Windows/Linux), or a software
  fallback. The private key never leaves the hardware.
- **No plaintext credentials on disk.** Cached credentials are stored as
  ECIES ciphertext. Plaintext exists only briefly in process memory.
- **No ambient environment variables.** The AWS CLI fetches credentials on
  demand via `credential_process`. Credentials are never exported into the
  shell environment.
- **In-memory credential buffers are zeroized on drop.** All sensitive data
  uses `Zeroizing<Vec<u8>>` to prevent residual memory exposure.
- **File permissions are restrictive.** Directories are 0700, files are 0600.

### What awsenc does NOT protect against

- Root/admin compromise (root can call SE/TPM APIs or dump process memory)
- Kernel exploits
- Physical attacks on the Secure Enclave or TPM hardware
- Okta account compromise (if your Okta credentials are stolen, awsenc
  cannot prevent credential issuance)
- Software fallback key theft on Linux without TPM

See [DESIGN.md](DESIGN.md) for the full security model and threat analysis.

## Dependencies

awsenc uses a conservative set of dependencies. Key external crates:

- `enclaveapp-*`: Shared hardware-backed key management (libenclaveapp)
- `reqwest` + `rustls`: HTTPS client for Okta and AWS STS
- `clap`: CLI argument parsing
- `serde`, `toml`: Configuration serialization
- `zeroize`: Secure memory wiping
- `crossterm`: Terminal UI for interactive profile picker

All dependencies are published on crates.io and are widely used in the
Rust ecosystem.
