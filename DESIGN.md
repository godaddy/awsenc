# awsenc Design Document

## Problem Statement

AWS credentials are routinely exposed through ambient environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`) or written to plaintext files (`~/.aws/credentials`). Tools like `aws-okta-processor` obtain temporary credentials from Okta but still hand them off as plaintext -- either exported into the shell environment or written to disk cache files. Any process running in the user's session can read these credentials, and any disk compromise exposes them.

This is the same class of "ambient security" problem that `sshenc` solves for SSH keys: secrets sitting around in the open, available to any malware, rogue dependency, or accidental log statement.

## Goals

1. **Eliminate plaintext credential storage.** AWS session credentials are encrypted at rest using hardware-backed keys (Secure Enclave on macOS, TPM 2.0 on Windows). Plaintext credentials exist only briefly in process memory.
2. **Eliminate ambient environment variables.** Credentials are never exported into the shell. The AWS CLI fetches them on demand via `credential_process`.
3. **Replace aws-okta-processor.** Provide the same Okta SAML -> AWS STS authentication flow as a single static binary with no Python runtime dependency.
4. **Cross-platform parity.** Support macOS, Windows (PowerShell, Git Bash), WSL, and Linux with the same binary and consistent behavior.
5. **Architectural consistency with sshenc.** Share the same platform abstraction patterns, workspace layout, build conventions, and security posture.

## Non-Goals

- Replacing AWS IAM Identity Center (SSO) for organizations that use it natively. `awsenc` targets environments that authenticate through Okta SAML.
- Key management or SSH functionality. That's `sshenc`.
- General-purpose secret storage. `awsenc` manages AWS credentials only.
- Supporting MFA factors beyond what Okta exposes (push, TOTP, YubiKey, WebAuthn).

---

## Architecture Overview

```
                   AWS CLI / SDK
                       |
                credential_process
                       |
                  awsenc serve
                       |
            +----------+----------+
            |                     |
       Cache Hit              Cache Miss
       (decrypt)              (authenticate)
            |                     |
     Secure Enclave /        Okta SAML Flow
     TPM decrypt             + AWS STS
            |                     |
       Return JSON           Encrypt + Cache
            |                     |
            +----------+----------+
                       |
              JSON to stdout
         {Version, AccessKeyId,
          SecretAccessKey,
          SessionToken, Expiration}
```

### Core Concept

The AWS CLI's `credential_process` setting invokes an external program whenever credentials are needed. `awsenc serve` is that program. It:

1. Reads the encrypted credential cache for the requested profile.
2. If cached credentials exist and are not expired: decrypts via Secure Enclave / TPM, returns JSON.
3. If expired or missing: authenticates with Okta, assumes the AWS role via STS, encrypts the new credentials with hardware-backed keys, writes the cache, and returns JSON.

The AWS CLI never sees a file or environment variable -- it calls `awsenc serve` and gets credentials back as JSON on stdout.

---

## Workspace Structure

4-crate workspace plus shared dependencies from
[libenclaveapp](https://github.com/godaddy/libenclaveapp):

```
awsenc/
  Cargo.toml                    # workspace root

  awsenc-core/                  # Platform-independent domain logic
    src/
      config.rs                 # Configuration loading (TOML + env vars)
      cache.rs                  # Credential cache format, lifecycle
      credential.rs             # AWS credential types
      okta.rs                   # Okta session, SAML assertion
      sts.rs                    # AWS STS AssumeRoleWithSAML
      mfa.rs                    # MFA factor handling
      profile.rs                # AWS profile management

  # NOTE: awsenc-secure-storage was replaced by enclaveapp-app-storage
  # (shared crate in libenclaveapp). See enclaveapp-app-storage for the
  # platform detection, key init, and encrypt/decrypt implementation.

  awsenc-cli/                   # Main CLI binary
    src/
      cli.rs                    # clap argument parsing
      serve.rs                  # credential_process handler
      auth.rs                   # Interactive authentication flow
      install.rs                # AWS config setup
      shell_init.rs             # Shell integration (export detection)
      exec.rs                   # Secure child process execution
      picker.rs                 # Interactive profile picker (MRU, filter, selection)
      usage.rs                  # MRU tracking (usage.json read/write)

  awsenc-tpm-bridge/            # Windows TPM bridge for WSL
    src/
      main.rs                   # JSON-RPC server over stdin/stdout
      tpm.rs                    # CNG encrypt/decrypt via enclaveapp-bridge
```

### Crate Responsibilities

| Crate | Role |
|-------|------|
| `awsenc-core` | Config, cache, Okta auth, STS, credential types |
| `awsenc-cli` | CLI binary, credential_process handler, interactive picker |
| `awsenc-tpm-bridge` | WSL-to-Windows TPM bridge (uses enclaveapp-bridge) |

### libenclaveapp Dependency

All platform-specific crypto is delegated to libenclaveapp. The `awsenc-cli`
crate uses `enclaveapp-app-storage` (shared crate) for platform-detected
hardware-backed encrypt/decrypt via the `EncryptionStorage` trait. The old
`awsenc-secure-storage` crate has been removed — its functionality is now
in `enclaveapp-app-storage`.

---

## Platform Support

| Platform | Hardware Backend | Credential Storage | Notes |
|----------|-----------------|-------------------|-------|
| macOS (Apple Silicon / T2) | Secure Enclave | ECIES-encrypted files | P-256 via CryptoKit (enclaveapp-apple) |
| Windows (native) | TPM 2.0 | ECIES-encrypted files | CNG Platform Crypto Provider (enclaveapp-windows) |
| Windows (PowerShell) | TPM 2.0 | ECIES-encrypted files | Native binary |
| Windows (Git Bash) | TPM 2.0 | ECIES-encrypted files | Same Windows binary |
| WSL | TPM 2.0 (via bridge) | ECIES-encrypted files | JSON-RPC to `awsenc-tpm-bridge.exe` on host |
| Linux (with TPM) | TPM 2.0 | ECIES-encrypted files | tss-esapi (enclaveapp-linux-tpm) |
| Linux (no TPM) | Software | File-based AES-GCM | Software fallback; one-time warning |

### WSL Bridge Architecture

WSL bridge architecture:

```
WSL Linux                              Windows Host
  awsenc-cli                           awsenc-tpm-bridge.exe
     |                                       |
     +--- JSON-RPC over stdin/stdout --------+
     |    (base64-encoded payloads)          |
     |                                  TPM 2.0 CNG
     |                                  encrypt/decrypt
```

- Detection: Check `WSL_DISTRO_NAME` env var or `/proc/version` for "microsoft"/"wsl".
- Bridge path: `/mnt/c/Program Files/awsenc/awsenc-tpm-bridge.exe` or `/mnt/c/ProgramData/awsenc/awsenc-tpm-bridge.exe`.
- Protocol: JSON-RPC (`init`, `encrypt`, `decrypt`, `destroy` methods).

---

## Authentication Flow

### Okta SAML -> AWS STS

```
User                awsenc             Okta                 AWS STS
  |                   |                  |                     |
  |  awsenc auth      |                  |                     |
  |------------------>|                  |                     |
  |                   | POST /authn      |                     |
  |                   |----------------->|                     |
  |                   |   session_token  |                     |
  |                   |<-----------------|                     |
  |                   |                  |                     |
  |   MFA prompt      |  MFA challenge   |                     |
  |<------------------|----------------->|                     |
  |   MFA response    |  MFA verify      |                     |
  |------------------>|----------------->|                     |
  |                   |   session_token  |                     |
  |                   |<-----------------|                     |
  |                   |                  |                     |
  |                   | GET /app/saml    |                     |
  |                   |----------------->|                     |
  |                   | SAML assertion   |                     |
  |                   |<-----------------|                     |
  |                   |                  |                     |
  |                   | AssumeRoleWithSAML                     |
  |                   |--------------------------------------->|
  |                   |        AccessKeyId, SecretAccessKey,   |
  |                   |        SessionToken, Expiration        |
  |                   |<---------------------------------------|
  |                   |                  |                     |
  |                   | Encrypt + cache  |                     |
  |                   |                  |                     |
  |   credentials     |                  |                     |
  |<------------------|                  |                     |
```

### MFA Factor Support

| Factor | Type | Phase | Handling |
|--------|------|-------|----------|
| YubiKey (legacy OTP) | `token:hardware:yubico` | 1 | Prompt for OTP string; this is the primary factor in current use |
| Okta Verify Push | `push` | 1 | Poll for approval, timeout after 60s |
| Okta Verify TOTP | `token:software:totp` | 1 | Prompt for code |
| Google Authenticator | `token:software:totp` | 1 | Prompt for code |
| WebAuthn/FIDO2 | `webauthn` | Future | See below |

The factor to use is configurable per-profile. YubiKey legacy OTP is the highest priority since it's the primary factor used with `aws-okta-processor` today. For push notifications, `awsenc` polls the Okta verify endpoint at 2-second intervals until approved, denied, or timed out.

### WebAuthn / FIDO2 Status

WebAuthn is advertised as an available factor in Okta's `/api/v1/authn` MFA challenge response, but completing the ceremony from a CLI tool has never been made to work. The fundamental problem: the WebAuthn assertion step requires `navigator.credentials.get()`, which is a **browser-only API**. There is no way to call it from a terminal process.

The browser-based AWS console flow works fine because Okta runs the entire WebAuthn ceremony within the browser session. A CLI tool doesn't have that luxury.

The Okta verify endpoint (`/api/v1/authn/factors/{factorId}/verify`) for WebAuthn factors expects a `clientDataJSON` and `authenticatorData` payload that can only be produced by the browser's WebAuthn API. Even if you talk to the YubiKey directly via CTAP2, you'd need to fabricate the `clientDataJSON` with the correct origin, which Okta validates.

**Planned approach: Loopback redirect server**

This is the same pattern used by `gh auth login`, `gcloud auth login`, and similar CLI tools for browser-based auth:

```
awsenc                          Browser                        Okta
  |                                |                             |
  | Start HTTP server on           |                             |
  | 127.0.0.1:<random_port>       |                             |
  |                                |                             |
  | Open browser to Okta sign-in   |                             |
  | with redirect_uri=             |                             |
  |   http://localhost:PORT/callback                             |
  |------------------------------->|                             |
  |                                | User enters credentials     |
  |                                |---------------------------->|
  |                                |                             |
  |                                | WebAuthn challenge          |
  |                                |<----------------------------|
  |                                | User taps YubiKey / Touch ID|
  |                                |---------------------------->|
  |                                |                             |
  |                                | Redirect to localhost       |
  |                                |   ?session_token=...        |
  |<-------------------------------|                             |
  |                                |                             |
  | Shut down server               |                             |
  | Continue with SAML flow        |                             |
```

The CLI prints a message like `Waiting for browser authentication...` and blocks until the callback arrives or a timeout (120s) elapses. The browser handles the entire WebAuthn ceremony natively -- Okta never knows or cares that a CLI initiated it.

**Open question:** Whether Okta's sign-in flow supports a `redirect_uri` parameter that sends back a usable session token (vs. just completing a browser SSO session). If Okta only sets cookies and doesn't redirect with a token, we may need to:
- Use Okta's OAuth2 `/authorize` endpoint with PKCE instead of the `/authn` API, getting an authorization code back via the redirect.
- Or scrape the session cookie from the redirect and use it to fetch the SAML assertion.

This needs prototyping against GoDaddy's Okta instance to determine what's actually possible. Deferred to Phase 6 but with a clear implementation path. YubiKey legacy OTP is the proven, working path and is the only hardware MFA factor supported in Phase 1.

### Okta Session Caching

Okta sessions are expensive to establish (MFA required). The Okta session token is cached encrypted alongside AWS credentials but with a separate lifecycle:

- Okta sessions typically last 2 hours.
- Reuse the cached Okta session to obtain new SAML assertions without re-authenticating.
- If the Okta session is expired, trigger full re-authentication including MFA.

---

## Credential Cache Format

Binary cache format:

```
Offset  Length  Field
0       4       Magic bytes: "AWSE" (0x41 0x57 0x53 0x45)
4       1       Format version: 0x01
5       1       Flags (bit 0: has_okta_session)
6       8       Credential expiration (Unix epoch seconds, big-endian)
14      8       Okta session expiration (Unix epoch seconds, big-endian)
22      4       AWS ciphertext length (big-endian)
26      var     AWS credential ciphertext (ECIES blob)
26+N    4       Okta session ciphertext length (big-endian, 0 if no session)
30+N    var     Okta session ciphertext (ECIES blob, absent if length=0)
```

### Cache File Locations

```
macOS:   ~/.config/awsenc/<profile>.enc
Windows: %APPDATA%\awsenc\<profile>.enc
Linux:   ~/.config/awsenc/<profile>.enc (or keyring)
```

Profile names are sanitized: alphanumeric, hyphens, underscores only. No path traversal characters.

### Credential Lifecycle

Proactive refresh pattern, adapted for AWS STS credential behavior:

| State | Condition | Action |
|-------|-----------|--------|
| **Fresh** | > 10 min until expiration | Decrypt and return cached credentials |
| **Refresh** | < 10 min until expiration | Attempt re-authentication in background; return cached if still valid |
| **Expired** | Past expiration | Full re-authentication required |

AWS STS session credentials have a fixed expiration (default 1 hour, configurable 15 min to 12 hours via `--duration`). Unlike JWTs, they cannot be "refreshed" -- a new `AssumeRoleWithSAML` call is required. However, if the Okta session is still valid, this is transparent to the user (no MFA prompt).

### Encryption

ECIES encryption per platform:

- **macOS**: ECIES with cofactor X9.63 SHA-256 AES-GCM via Secure Enclave.
- **Windows**: ECDH P-256 + AES-GCM via CNG Platform Crypto Provider.
- **WSL**: Delegated to Windows host via TPM bridge.
- **Linux**: D-Bus Secret Service (software keyring). One-time warning on first use.

Hardware keys are non-exportable. The private key never leaves the Secure Enclave / TPM. Encryption uses the public key (fast, no hardware call); decryption requires the hardware (one SE/TPM operation per credential fetch).

---

## AWS CLI Integration

### credential_process Configuration

The primary integration point. Users configure `~/.aws/config`:

```ini
[profile my-account]
credential_process = /usr/local/bin/awsenc serve --profile my-account
region = us-west-2
```

When any AWS CLI command or SDK call uses this profile, it invokes `awsenc serve --profile my-account`, which returns:

```json
{
  "Version": 1,
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "SessionToken": "...",
  "Expiration": "2026-04-11T16:30:00Z"
}
```

The `Expiration` field tells the AWS CLI when to call `awsenc serve` again. If credentials are still fresh in the cache, the serve call returns in milliseconds (one SE/TPM decrypt operation).

### awsenc install

Automates the `~/.aws/config` setup, following the same pattern as `sshenc install` (comment-delimited managed blocks):

```ini
# --- BEGIN awsenc managed (my-account) ---
[profile my-account]
credential_process = /usr/local/bin/awsenc serve --profile my-account
# --- END awsenc managed (my-account) ---
```

This allows `awsenc install` and `awsenc uninstall` to be idempotent and safe alongside manually managed profiles.

---

## CLI Interface

### Commands

```
awsenc <COMMAND>

Commands:
  auth          Authenticate with Okta and cache AWS credentials
  serve         Output credentials as JSON (for credential_process)
  exec          Run a command with AWS credentials injected
  use           Set the active profile (with interactive picker)
  install       Configure AWS CLI profiles to use awsenc
  uninstall     Remove awsenc configuration from AWS CLI profiles
  list          List configured profiles and cache status
  clear         Clear cached credentials for a profile (or all)
  shell-init    Print shell integration script (export detection)
  config        Show configuration paths and current settings
  completions   Generate shell completions (bash, zsh, fish, powershell)
```

---

## Profile Selection and Ergonomics

Employees often have dozens of AWS profiles (dev, staging, prod across multiple accounts and roles). Requiring `--profile exact-name-here` every time is tedious and error-prone. `awsenc` tracks usage and provides an interactive picker to make this fast.

### MRU (Most Recently Used) Tracking

Every time a profile is used (`auth`, `serve`, `exec`, `use`), `awsenc` updates a usage log:

`~/.config/awsenc/usage.json`:

```json
{
  "profiles": {
    "prod-admin": { "last_used": "2026-04-11T14:30:00Z", "use_count": 47 },
    "dev-readonly": { "last_used": "2026-04-11T13:00:00Z", "use_count": 112 },
    "staging-deploy": { "last_used": "2026-04-10T09:15:00Z", "use_count": 23 }
  }
}
```

This file is lightweight (just timestamps and counts) and is not encrypted -- it contains profile names only, no credentials.

### Interactive Profile Picker

When `--profile` is omitted from `auth`, `exec`, or `use`, `awsenc` shows an interactive picker:

```
$ awsenc auth

  Recent profiles:
    1. prod-admin           (authenticated, expires in 43m)
    2. dev-readonly         (authenticated, expires in 2h 10m)
    3. staging-deploy       (expired)
    4. prod-billing-ro      (authenticated, expires in 55m)
    5. dev-data-pipeline    (expired)

  All profiles:
    6.  cert-manager-prod
    7.  cert-manager-staging
    8.  compliance-audit
    9.  data-lake-prod
    10. data-lake-staging
    ...

  Select profile [1-42] or type to filter: _
```

Key features:

- **Top 5 MRU** shown first, separated from the full list.
- **Cache status** shown inline (authenticated + time remaining, expired, or uncached).
- **Type-to-filter**: Typing narrows the list with fuzzy matching. `prod` shows only profiles containing "prod". This is critical with 40+ profiles.
- **Number selection**: Press a number to pick directly. No arrow-key navigation needed (works over slow SSH connections, basic terminals).
- **Direct match shortcut**: If the typed filter matches exactly one profile, auto-select it.

Implementation: Use `crossterm` for raw terminal input and ANSI rendering. No heavy TUI framework -- keep it lean and fast. The picker is a single screen, not a full-screen takeover.

### awsenc use

Sets the "active" profile for the current shell session. This avoids typing `--profile` on every command:

```
$ awsenc use                    # interactive picker
$ awsenc use prod-admin         # direct selection
$ awsenc use 1                  # pick by MRU rank
```

`awsenc use` sets `AWSENC_PROFILE` in the current shell (via the shell-init hook). Subsequent commands pick it up:

```
$ awsenc use prod-admin
Switched to profile: prod-admin

$ aws s3 ls                     # credential_process reads AWSENC_PROFILE
$ awsenc exec -- terraform plan # uses active profile
$ awsenc auth                   # refreshes active profile
```

**How it works with credential_process:** The `credential_process` line in `~/.aws/config` can reference the active profile:

```ini
[profile active]
credential_process = /usr/local/bin/awsenc serve --active
```

`awsenc serve --active` reads `AWSENC_PROFILE` and serves credentials for that profile. Users who prefer explicit profiles still use `--profile name` directly.

For users who want a dedicated AWS profile per account (the common case), each profile still has its own `credential_process` line and works independently. `awsenc use` is an additional convenience, not a replacement.

### Shell Integration for Profile Switching

The `awsenc shell-init` hook (already described for export detection) also provides:

**Active profile in prompt** (opt-in):

```bash
# awsenc adds to PS1 / PROMPT when a profile is active:
[aws:prod-admin] $
```

**awsenc use** as a shell function (not a subprocess):

Since `awsenc use` needs to set an env var in the *parent* shell, it must be a shell function, not a standalone binary call. `awsenc shell-init` emits:

```bash
# bash/zsh
awsenc-use() {
  local profile
  profile=$(/usr/local/bin/awsenc use "$@" --print-profile) || return $?
  export AWSENC_PROFILE="$profile"
  export AWS_PROFILE="$profile"
}
```

```powershell
# PowerShell
function awsenc-use {
  $profile = & awsenc use @args --print-profile
  if ($LASTEXITCODE -eq 0) {
    $env:AWSENC_PROFILE = $profile
    $env:AWS_PROFILE = $profile
  }
}
```

`awsenc use --print-profile` runs the picker (or takes the argument), prints the selected profile name to stdout, and exits. The shell function captures it and sets the env vars. This way the binary doesn't need to manipulate the parent shell's environment directly.

### Aliases and Favorites

For profiles used constantly, users can define short aliases in `~/.config/awsenc/config.toml`:

```toml
[aliases]
prod = "mycompany-production-admin"
dev = "mycompany-development-readonly"
stg = "mycompany-staging-deploy"
```

Then:

```
$ awsenc auth prod
$ awsenc exec dev -- aws s3 ls
$ awsenc use stg
```

### awsenc auth (updated)

Interactive authentication. If `--profile` is omitted, shows the interactive profile picker.

```
awsenc auth                              # interactive picker
awsenc auth --profile my-account         # explicit profile
awsenc auth prod                         # alias
awsenc auth --profile my-account --factor push --duration 3600
```

### awsenc serve

Non-interactive. Returns credentials as JSON to stdout. This is what `credential_process` calls. If credentials are cached and valid, returns them immediately. If expired, attempts transparent re-auth using cached Okta session. If Okta session is also expired, exits non-zero with an error on stderr instructing the user to run `awsenc auth`.

```
awsenc serve --profile my-account
```

Output:
```json
{
  "Version": 1,
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "SessionToken": "...",
  "Expiration": "2026-04-11T16:30:00Z"
}
```

The separation of `auth` (interactive) and `serve` (non-interactive) is deliberate. `credential_process` must not block on user input -- if it can't return credentials silently, it fails fast and the user runs `awsenc auth` explicitly.

### awsenc exec

Run a child process with AWS credentials injected into its environment only. Credentials never appear in the parent shell:

```
awsenc exec --profile my-account -- terraform apply
awsenc exec prod -- aws s3 ls               # alias
awsenc exec -- terraform apply              # uses active profile (AWSENC_PROFILE)
```

The child process inherits `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN` but these are scoped to the child only.

Profile resolution order: explicit `--profile` flag > positional alias/name > `AWSENC_PROFILE` env var. If none are set and no `--` separator is present, shows the interactive picker.

### awsenc install / uninstall

```
awsenc install --profile my-account \
  --organization mycompany.okta.com \
  --application https://mycompany.okta.com/home/amazon_aws/0oa.../272 \
  --role arn:aws:iam::123456789012:role/MyRole

awsenc uninstall --profile my-account
```

`install` writes:
1. A managed block in `~/.aws/config` with the `credential_process` directive.
2. Profile-specific configuration in `~/.config/awsenc/profiles/<name>.toml`.

`uninstall` removes both.

### awsenc shell-init

Prints a shell snippet that detects and warns when AWS credentials are exported as environment variables:

```bash
# Add to .zshrc / .bashrc:
eval "$(awsenc shell-init)"
```

The shell hook intercepts `export AWS_ACCESS_KEY_ID=...` and similar patterns, printing a warning:

```
[awsenc] Warning: Exporting AWS credentials as environment variables defeats
hardware-backed protection. Use 'awsenc exec' or credential_process instead.
```

Supported shells: bash (DEBUG trap), zsh (preexec hook), fish (function wrapper), PowerShell (prompt function).

---

## Configuration

### Global Configuration

`~/.config/awsenc/config.toml`:

```toml
# Okta settings (defaults for all profiles)
[okta]
organization = "mycompany.okta.com"
user = "jdoe"
default_factor = "push"

# Hardware settings
[security]
biometric = false           # Require Touch ID / Windows Hello per decrypt

# Cache settings
[cache]
refresh_window_seconds = 600  # Start background refresh 10 min before expiry
```

### Per-Profile Configuration

`~/.config/awsenc/profiles/<name>.toml`:

```toml
[okta]
organization = "mycompany.okta.com"     # Override global
application = "https://mycompany.okta.com/home/amazon_aws/0oa.../272"
role = "arn:aws:iam::123456789012:role/MyRole"
factor = "push"                          # Override global
duration = 3600                          # STS session duration in seconds

[okta.secondary_role]                    # Optional chained role assumption
role_arn = "arn:aws:iam::987654321098:role/CrossAccountRole"
```

### Configuration Precedence

CLI flags > Environment variables (`AWSENC_*`) > Per-profile TOML > Global TOML > Defaults

### Environment Variables

| Variable | Purpose |
|----------|---------|
| `AWSENC_OKTA_USER` | Okta username |
| `AWSENC_OKTA_ORG` | Okta organization FQDN |
| `AWSENC_OKTA_APP` | Okta application URL |
| `AWSENC_FACTOR` | Default MFA factor |
| `AWSENC_BIOMETRIC` | Require biometric (`true`/`false`) |

Note: No `AWSENC_OKTA_PASS` variable. Passwords are prompted interactively or retrieved from the system keychain. We do not encourage ambient password storage.

---

## Password Handling

Unlike `aws-okta-processor` which accepts passwords via `AWS_OKTA_PASS` environment variable, `awsenc` takes a defense-in-depth approach:

1. **Interactive prompt** (default): Secure terminal input with no echo.
2. **System keychain** (optional): Store the Okta password in macOS Keychain / Windows Credential Manager using the same hardware-backed storage. Retrieve it automatically on subsequent runs.
3. **Stdin pipe** (for automation): `echo "$pass" | awsenc auth --profile foo --pass-stdin`. Documented but discouraged for interactive use.

No environment variable for passwords. This is intentional and a departure from `aws-okta-processor`.

---

## Security Model

### What Is Protected

| Asset | Protection |
|-------|-----------|
| AWS session credentials at rest | ECIES encrypted, hardware-bound key |
| AWS session credentials in transit | Only in process memory, only during `serve` / `exec` |
| Okta session token at rest | ECIES encrypted alongside AWS credentials |
| Okta password | Interactive prompt or system keychain; never on disk or in env |
| Hardware encryption key | Non-exportable, generated inside SE/TPM |

### What Is NOT Protected

| Threat | Status | Mitigation |
|--------|--------|-----------|
| Root/admin compromise | Out of scope | Root can attach to any process and read memory |
| Kernel exploit | Out of scope | Same as above |
| Process memory read by same-user malware | Partial | Zeroize on drop; minimal exposure window |
| Credential forwarded to attacker by compromised tool | Partial | `exec` mode limits blast radius to child process |
| Okta account compromise | Out of scope | MFA helps; this is an Okta responsibility |
| Phishing of MFA push approval | Partial | Display context in push notification; user vigilance |

### Memory Safety

- `Zeroizing<Vec<u8>>` wrappers for all credential buffers.
- `unsafe` code denied at workspace level except FFI callsites.
- No `unwrap()` or `panic!()` in non-test code.

### File Permissions

- `~/.config/awsenc/` directory: 0700
- All `.enc` cache files: 0600
- All `.toml` config files: 0600
- Binary: standard executable permissions

---

## Build System

### Toolchain

- Rust 2021 edition, minimum 1.75
- Cargo workspace
- Makefile for orchestration (matching `sshenc` pattern)

### Makefile Targets

```makefile
build:      cargo build --release
install:    cp binaries to $(PREFIX)/bin, bridge to platform-specific location
uninstall:  remove installed binaries
test:       cargo test --workspace
lint:       cargo clippy --workspace -- -D warnings
fmt:        cargo fmt --all -- --check
clean:      cargo clean
```

### Dependencies

| Crate | Purpose |
|-------|---------|
| clap 4 | CLI parsing with derive macros and completions |
| reqwest + rustls | HTTP client (Okta API, STS) -- no OpenSSL dependency |
| serde + serde_json | JSON serialization (credential_process output, Okta API) |
| toml | Configuration files |
| security-framework | macOS Secure Enclave bindings |
| windows 0.58 | Windows CNG/TPM bindings |
| keyring 3 | Linux D-Bus Secret Service |
| zeroize | Secure memory wiping |
| base64 | Encoding for SAML assertions and bridge protocol |
| dirs 6 | XDG/platform config directory resolution |
| sha2 | Cache file integrity |
| chrono | Timestamp handling for credential expiration |
| tracing | Structured logging |
| thiserror | Error type definitions |
| tokio | Async runtime (for Okta polling, future extensibility) |
| crossterm | Raw terminal input, ANSI rendering for interactive profile picker |

### Compilation Targets

| Target | Binary | Notes |
|--------|--------|-------|
| aarch64-apple-darwin | awsenc | Apple Silicon |
| x86_64-apple-darwin | awsenc | Intel Mac |
| x86_64-pc-windows-msvc | awsenc.exe, awsenc-tpm-bridge.exe | Windows native |
| x86_64-unknown-linux-gnu | awsenc | Linux / WSL |
| aarch64-unknown-linux-gnu | awsenc | Linux ARM |

### Distribution

| Channel | Format |
|---------|--------|
| GitHub Releases | tar.gz (Unix), zip + MSI (Windows) |
| Homebrew | Tap formula (`brew install godaddy/tap/awsenc`) |
| Scoop | Bucket manifest (Windows) |

The Windows MSI installs both `awsenc.exe` and `awsenc-tpm-bridge.exe`, and optionally installs the Linux binary into detected WSL distros.

---

## Migration from aws-okta-processor

### Compatibility Strategy

`awsenc` is a drop-in replacement for `aws-okta-processor`'s `credential_process` mode. The migration path:

1. Install `awsenc`.
2. Run `awsenc install` for each profile (or migrate manually).
3. Remove `aws-okta-processor` references from `~/.aws/config` / `~/.aws/credentials`.
4. Uninstall `aws-okta-processor`.

### Configuration Translation

| aws-okta-processor | awsenc |
|-------------------|--------|
| `--user` / `AWS_OKTA_USER` | `--user` / `AWSENC_OKTA_USER` / config `okta.user` |
| `--organization` / `AWS_OKTA_ORGANIZATION` | `--organization` / `AWSENC_OKTA_ORG` / config `okta.organization` |
| `--application` / `AWS_OKTA_APPLICATION` | `--application` / `AWSENC_OKTA_APP` / config `okta.application` |
| `--role` / `AWS_OKTA_ROLE` | `--role` / config `okta.role` |
| `--factor` / `AWS_OKTA_FACTOR` | `--factor` / `AWSENC_FACTOR` / config `okta.factor` |
| `--duration` / `AWS_OKTA_DURATION` | `--duration` / config `okta.duration` |
| `--secondary-role` | config `okta.secondary_role.role_arn` |
| `--environment` | `awsenc exec` (no direct equivalent; env export is discouraged) |
| `--key` | `--profile` (profile name serves as cache key) |
| `--pass` / `AWS_OKTA_PASS` | Interactive prompt or keychain (no env var) |

### awsenc migrate

Optional migration helper:

```
awsenc migrate
```

Scans `~/.aws/config` and `~/.aws/credentials` for `credential_process=aws-okta-processor` entries, parses their flags, and generates equivalent `awsenc` profile configs. Writes the new config files and updates `~/.aws/config` with `credential_process=awsenc serve` directives. The original entries are commented out, not deleted.

---

## Shell Integration Details

### Export Detection

The shell hook warns when users attempt to export AWS credentials into their environment:

**Detected patterns:**
- `export AWS_ACCESS_KEY_ID=...`
- `export AWS_SECRET_ACCESS_KEY=...`
- `export AWS_SESSION_TOKEN=...`
- `declare -x AWS_ACCESS_KEY_ID=...`
- Fish: `set -gx AWS_ACCESS_KEY_ID ...`
- PowerShell: `$env:AWS_ACCESS_KEY_ID = ...`

**Shell-specific hooks:**

| Shell | Mechanism | Invasiveness |
|-------|-----------|-------------|
| zsh | `preexec` via `add-zsh-hook` | Clean; standard hook |
| bash | `DEBUG` trap on `BASH_COMMAND` | Chains with existing traps |
| fish | Function wrapper | Minimal |
| PowerShell | `Set-PSReadLineKeyHandler` or prompt function | Moderate |

### PowerShell Integration

PowerShell on Windows gets first-class support (matching the `sshenc` pattern for Windows shells):

```powershell
# Add to $PROFILE:
Invoke-Expression (awsenc shell-init powershell)
```

The PowerShell hook overrides `Set-Item` and direct `$env:` assignment to detect and warn on AWS credential exports.

---

## Detailed Command Reference

### awsenc auth

```
awsenc auth [OPTIONS] [PROFILE]

Arguments:
  [PROFILE]                     Profile name or alias (omit for interactive picker)

Options:
  -p, --profile <NAME>          Profile name (alternative to positional arg)
  -u, --user <USER>             Okta username (overrides config)
  -o, --organization <FQDN>    Okta organization (overrides config)
  -a, --application <URL>       Okta application URL (overrides config)
  -r, --role <ARN>              AWS role ARN (overrides config)
  -f, --factor <TYPE>           MFA factor type (overrides config)
  -d, --duration <SECONDS>      STS session duration (default: 3600)
      --biometric               Require biometric for this session's cache
      --no-open                 Don't auto-open browser for WebAuthn
      --pass-stdin              Read password from stdin
```

Profile resolution: positional arg > `--profile` flag > `AWSENC_PROFILE` env var > interactive picker.

### awsenc serve

```
awsenc serve [OPTIONS]

Options:
  -p, --profile <NAME>          Profile name (required unless --active)
      --active                  Use AWSENC_PROFILE env var
```

Exits 0 with JSON on stdout if credentials available. Exits non-zero with diagnostic on stderr if interactive auth required. Never interactive -- no picker, no prompts.

### awsenc exec

```
awsenc exec [OPTIONS] [PROFILE] -- <COMMAND> [ARGS...]

Arguments:
  [PROFILE]                     Profile name or alias (before --)

Options:
  -p, --profile <NAME>          Profile name (alternative to positional arg)
```

Injects `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, and `AWS_DEFAULT_REGION` (if configured) into the child process environment. Forwards the child's exit code.

Profile resolution: positional arg > `--profile` flag > `AWSENC_PROFILE` env var > interactive picker (if stdin is a TTY).

### awsenc use

```
awsenc use [PROFILE]

Arguments:
  [PROFILE]                     Profile name, alias, or MRU rank number
```

Sets the active profile for the current shell session. Must be invoked through the shell function installed by `awsenc shell-init` (so it can set env vars in the parent shell). Without arguments, shows the interactive picker.

Output (with `--print-profile`): prints the resolved profile name to stdout and exits. Used by the shell function wrapper.

### awsenc install

```
awsenc install [OPTIONS] [PROFILE]

Arguments:
  [PROFILE]                     Profile name (omit for interactive picker)

Options:
  -p, --profile <NAME>          Profile name (alternative to positional arg)
  -u, --user <USER>             Okta username
  -o, --organization <FQDN>    Okta organization FQDN
  -a, --application <URL>       Okta application URL
  -r, --role <ARN>              AWS role ARN
  -f, --factor <TYPE>           Default MFA factor
  -d, --duration <SECONDS>      Default STS session duration
      --region <REGION>         AWS region for this profile
      --biometric               Require biometric for decryption
```

### awsenc list

```
awsenc list [OPTIONS]

Options:
      --json                    Output as JSON
      --all                     Show all profiles (default: MRU order, top 10)
```

Shows configured profiles sorted by MRU with cache status:

```
$ awsenc list
  Profile                      Status              Expires
  prod-admin              *    authenticated        43m
  dev-readonly                 authenticated        2h 10m
  staging-deploy               expired              --
  prod-billing-ro              authenticated        55m
  dev-data-pipeline            expired              --
  ... (35 more, use --all to show)

  * = active profile
```

### awsenc clear

```
awsenc clear [OPTIONS] [PROFILE]

Arguments:
  [PROFILE]                     Profile name or alias (omit for interactive picker)

Options:
  -p, --profile <NAME>          Profile name
      --all                     Clear all cached credentials
      --force                   Skip confirmation prompt
```

### awsenc migrate

```
awsenc migrate [OPTIONS]

Options:
      --dry-run                 Show what would change without modifying files
      --force                   Overwrite existing awsenc profiles
```

---

## Testing Strategy

Following the testing patterns from `sshenc` (159 tests, 6 categories):

### Test Categories

1. **Unit tests**: Config parsing, cache format encode/decode, credential serialization, profile management, SAML parsing.
2. **Mock storage tests**: Full auth flow with mock `SecureStorage` impl. No hardware required.
3. **HTTP mock tests**: Okta API and STS API responses using `wiremock` or `mockito`. Test MFA flows, error cases, session reuse.
4. **Integration tests**: CLI invocation tests (`assert_cmd`). Test `serve` output format, `install`/`uninstall` idempotency, `exec` environment isolation.
5. **Cache lifecycle tests**: Fresh/refresh/expired state transitions with controlled timestamps.
6. **Hardware integration tests**: Actual SE/TPM encrypt/decrypt. Requires hardware; skipped in CI. Tagged `#[ignore]` and run manually.

### CI

GitHub Actions with matrix builds across macOS, Windows, and Linux. Hardware tests skipped in CI (same approach as `sshenc`).

---

## Implementation Phases

### Phase 1: Foundation

- Workspace skeleton, build system, CI pipeline.
- `awsenc-secure-storage` with macOS Secure Enclave and mock backends.
- `awsenc-core` with config loading and cache format.
- `awsenc-cli` with `config` and `completions` commands.
- Unit and mock tests.

### Phase 2: Authentication

- Okta authentication flow (session, MFA, SAML).
- MFA factors: YubiKey legacy OTP (priority), Okta push, TOTP.
- AWS STS `AssumeRoleWithSAML`.
- `awsenc auth` command.
- `awsenc serve` command (credential_process output).
- HTTP mock tests for Okta and STS.

### Phase 3: AWS CLI Integration

- `awsenc install` / `awsenc uninstall`.
- `awsenc list` and `awsenc clear`.
- `awsenc exec`.
- Integration tests.

### Phase 4: Windows and Cross-Platform

- Windows TPM backend (`awsenc-secure-storage/windows.rs`).
- WSL TPM bridge (`awsenc-tpm-bridge`).
- Linux keyring backend.
- Windows MSI installer.
- `awsenc shell-init` for all shells including PowerShell.

### Phase 5: Migration and Polish

- `awsenc migrate` command.
- Homebrew formula, Scoop manifest.
- Threat model document.
- README and user documentation.
- Secondary role assumption (chained AssumeRole).
- Okta password keychain integration.

### Phase 6: WebAuthn via Browser Loopback

- Implement local HTTP server (bind `127.0.0.1`, random port, short-lived).
- Prototype against GoDaddy's Okta to determine the right auth endpoint:
  - Option A: Okta OAuth2 `/authorize` with PKCE -- get authorization code via redirect, exchange for session.
  - Option B: Okta sign-in widget URL with redirect -- capture session token from callback.
- Open browser with `open` crate, fall back to `$BROWSER`.
- CLI blocks with spinner/message, timeout after 120s.
- On callback: extract session token, shut down server, continue with SAML assertion fetch.
- Add `--factor webauthn` / `--factor browser` option to `awsenc auth`.
- Works for any browser-based MFA factor, not just WebAuthn (future-proofs for Okta FastPass, etc.).

---

## Open Questions

1. **Okta Identity Engine compatibility.** `aws-okta-processor` has known issues with newer Okta Identity Engine. We should target the OIE APIs from the start rather than the Classic Engine, or support both with detection.

2. **WebAuthn/FIDO2 for Okta MFA.** Known broken in GoDaddy's Okta API -- the verify callback doesn't fire after the user completes the WebAuthn flow in the browser. Works fine in the browser-based AWS console flow (Okta handles it natively). Deferred until we can diagnose whether this is an Okta Classic vs Identity Engine issue, a GoDaddy configuration gap, or an API limitation. Options: local CTAP2, embedded WebView, or loopback redirect server.

3. **Concurrent profile access.** If multiple terminal sessions call `awsenc serve` for the same profile simultaneously, the cache file needs safe concurrent access. File locking (flock/LockFileEx) should suffice since operations are fast.

4. **AWS SSO / IAM Identity Center.** Some teams may be migrating from Okta SAML to native AWS SSO. Should `awsenc` also support the AWS SSO OIDC flow as an alternative auth backend? This could be a future extension but shouldn't complicate the initial design.
