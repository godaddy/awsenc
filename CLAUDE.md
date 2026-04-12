# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`awsenc` is a hardware-backed AWS credential manager. It encrypts temporary AWS credentials (from Okta SAML federation) using the Secure Enclave (macOS) or TPM 2.0 (Windows), so credentials never exist as plaintext on disk. Uses `credential_process` integration with the AWS CLI.

## Build & Development

Rust workspace. Requires Rust 1.75+. macOS builds need Xcode (for swiftc via libenclaveapp).

```bash
cargo build --workspace
cargo test --workspace --features awsenc-secure-storage/mock
cargo clippy --workspace --all-targets --features awsenc-secure-storage/mock -- -D warnings
cargo fmt --all -- --check
```

The `mock` feature on `awsenc-secure-storage` replaces the hardware backend with a test mock. Required for tests on any platform.

## Architecture

Rust workspace with 4 crates:

- **awsenc-core** -- Okta SAML authentication, STS AssumeRoleWithSAML, credential caching (binary format with encrypted payloads), config management, MFA support (push/TOTP/YubiKey).
- **awsenc-secure-storage** -- Platform abstraction for encrypt/decrypt. macOS uses `enclaveapp-apple` (CryptoKit ECIES), Windows uses `enclaveapp-windows` (CNG ECIES), WSL uses `enclaveapp-bridge`, Linux uses software AES fallback.
- **awsenc-cli** -- Main CLI binary. Commands: auth, serve, exec, install, uninstall, list, clear, shell-init, config.
- **awsenc-tpm-bridge** -- Windows TPM bridge for WSL (JSON-RPC over stdin/stdout).

### Key Flow

1. `awsenc auth` -- Okta username/password + MFA -> SAML assertion -> STS AssumeRoleWithSAML -> encrypt credentials -> cache
2. `awsenc serve` -- AWS CLI calls this via `credential_process` -> decrypt cache -> return JSON credentials
3. Cache auto-refreshes via Okta session token (2hr window) without re-authentication

### Dependencies

Uses `libenclaveapp` (path dependency at `../libenclaveapp/`) for all hardware-backed cryptography. The `enclaveapp-wsl` crate provides WSL shell integration.

## Platform

- macOS: Secure Enclave via CryptoKit (libenclaveapp)
- Windows: TPM 2.0 via CNG (libenclaveapp)
- WSL: JSON-RPC bridge to Windows TPM
- Linux: Software AES-256-GCM fallback with keyring encryption
