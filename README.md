# awsenc

Hardware-backed AWS credential manager. Encrypts AWS session credentials at rest using the **Secure Enclave** (macOS) or **TPM 2.0** (Windows/WSL). Integrates directly with the AWS CLI via `credential_process` — no plaintext credentials on disk or in environment variables.

Replaces [aws-okta-processor](https://github.com/godaddy/aws-okta-processor) with a single static binary. No Python runtime required.

Part of the same family as [sshenc](https://github.com/godaddy/sshenc) (SSH keys).

## Install

**[Download latest release](https://github.com/godaddy/awsenc/releases/latest)** -- pre-built binaries for macOS, Windows, and Linux.

### Homebrew (macOS)

```sh
brew tap godaddy/awsenc
brew install awsenc
```

### Windows -- MSI installer

Download `awsenc-x86_64-pc-windows-msvc.msi` from the
[latest release](https://github.com/godaddy/awsenc/releases). Double-click
to install.

### Windows -- Scoop

```powershell
scoop bucket add awsenc https://github.com/godaddy/scoop-awsenc
scoop install awsenc
```

### Linux -- tarball

```sh
tar xzf awsenc-x86_64-unknown-linux-gnu.tar.gz
sudo cp awsenc awsenc-tpm-bridge /usr/local/bin/
```

### From source

```sh
git clone https://github.com/godaddy/awsenc.git
cd awsenc
make build
make install        # installs to /usr/local/bin
```

## Quick Start

### 1. Set up a profile

```sh
awsenc install --profile my-account \
  --organization mycompany.okta.com \
  --application https://mycompany.okta.com/home/amazon_aws/0oa.../272 \
  --role arn:aws:iam::123456789012:role/MyRole \
  --factor yubikey
```

This writes a `credential_process` entry in `~/.aws/config` and saves the Okta settings to `~/.config/awsenc/profiles/my-account.toml`.

### 2. Authenticate

```sh
awsenc auth my-account
```

Prompts for your Okta password and MFA (YubiKey OTP, push, or TOTP). Credentials are encrypted with your Secure Enclave / TPM key and cached locally.

### 3. Use AWS normally

```sh
aws s3 ls --profile my-account
```

The AWS CLI calls `awsenc serve` under the hood. Cached credentials are decrypted from hardware in milliseconds. No environment variables, no plaintext files.

## Commands

| Command | Description |
|---------|-------------|
| `awsenc auth [PROFILE]` | Authenticate with Okta and cache encrypted credentials |
| `awsenc serve --profile NAME` | Output credentials as JSON for `credential_process` |
| `awsenc exec [PROFILE] -- CMD` | Run a command with credentials injected into its environment only |
| `awsenc use [PROFILE]` | Set the active profile for the current shell session |
| `awsenc install` | Configure an AWS CLI profile to use awsenc |
| `awsenc uninstall` | Remove awsenc configuration from AWS CLI |
| `awsenc list` | List profiles with cache status |
| `awsenc clear` | Clear cached credentials |
| `awsenc shell-init [SHELL]` | Print shell integration script |
| `awsenc config` | Show configuration paths |
| `awsenc completions SHELL` | Generate shell completions |
| `awsenc migrate` | Migrate from aws-okta-processor |

## Interactive Profile Picker

When `--profile` is omitted, `awsenc` shows an interactive picker with your 5 most recently used profiles at the top:

```
  Recent profiles:
    1. prod-admin           (authenticated, expires in 43m)
    2. dev-readonly         (authenticated, expires in 2h 10m)
    3. staging-deploy       (expired)

  All profiles:
    4. cert-manager-prod    (not cached)
    5. data-lake-staging    (not cached)
    ...

  Select profile [1-42] or type to filter: _
```

Type to fuzzy-filter, or press a number to pick directly.

## Shell Integration

Add to your shell RC file:

```sh
# bash (~/.bashrc)
eval "$(awsenc shell-init bash)"

# zsh (~/.zshrc)
eval "$(awsenc shell-init zsh)"

# fish (~/.config/fish/config.fish)
awsenc shell-init fish | source

# PowerShell ($PROFILE)
Invoke-Expression (awsenc shell-init powershell)
```

This provides:
- **Export detection** — warns if you try to `export AWS_ACCESS_KEY_ID=...`
- **`awsenc-use`** — shell function to switch active profiles (sets `AWS_PROFILE` and `AWSENC_PROFILE`)

## Profile Aliases

Define short aliases in `~/.config/awsenc/config.toml`:

```toml
[aliases]
prod = "mycompany-production-admin"
dev = "mycompany-development-readonly"
stg = "mycompany-staging-deploy"
```

Then: `awsenc auth prod`, `awsenc exec dev -- terraform plan`, etc.

## How It Works

```
AWS CLI / SDK
     |
credential_process = awsenc serve --profile NAME
     |
     v
awsenc serve
     |
  Cache hit? ─── Yes ──> Decrypt with Secure Enclave / TPM ──> JSON to stdout
     |
     No
     |
  Okta session cached? ─── Yes ──> Get SAML assertion ──> STS AssumeRole
     |                                                          |
     No                                                    Encrypt + cache
     |                                                          |
  Exit 1 (run `awsenc auth`)                              JSON to stdout
```

Credentials are encrypted using **ECIES** (P-256, X9.63 KDF, AES-GCM) with a hardware-bound key. The private key never leaves the Secure Enclave or TPM.

## MFA Factors

| Factor | Type | Status |
|--------|------|--------|
| YubiKey (legacy OTP) | `yubikey` | Supported |
| Okta Verify Push | `push` | Supported |
| Okta/Google TOTP | `totp` | Supported |
| WebAuthn/FIDO2 | — | [Planned](DESIGN.md#webauthn--fido2-status) |

## Platform Support

| Platform | Backend | Notes |
|----------|---------|-------|
| macOS (Apple Silicon / T2) | Secure Enclave | CryptoKit via libenclaveapp |
| Windows (native) | TPM 2.0 | CNG Platform Crypto Provider |
| WSL | TPM 2.0 via bridge | JSON-RPC to Windows host |
| Linux (with TPM) | TPM 2.0 | tss-esapi via libenclaveapp |
| Linux (no TPM) | Software fallback | File-based AES-GCM (one-time warning) |

All platform-specific crypto is provided by
[libenclaveapp](https://github.com/godaddy/libenclaveapp).

## Configuration

### Global: `~/.config/awsenc/config.toml`

```toml
[okta]
organization = "mycompany.okta.com"
user = "jdoe"
default_factor = "yubikey"

[security]
biometric = false

[cache]
refresh_window_seconds = 600

[aliases]
prod = "production-admin"
```

### Per-profile: `~/.config/awsenc/profiles/<name>.toml`

```toml
[okta]
organization = "mycompany.okta.com"
application = "https://mycompany.okta.com/home/amazon_aws/0oa.../272"
role = "arn:aws:iam::123456789012:role/MyRole"
factor = "yubikey"
duration = 3600
```

## Migrating from aws-okta-processor

```sh
awsenc migrate --dry-run    # preview changes
awsenc migrate              # convert all credential_process entries
```

This scans `~/.aws/config` for `aws-okta-processor` entries, creates equivalent awsenc profiles, and updates the `credential_process` directives. Original entries are commented out, not deleted.

## Security

- Credentials encrypted at rest with hardware-bound ECIES keys
- Private key never leaves Secure Enclave / TPM
- No plaintext credentials on disk or in environment variables
- `Zeroize`-on-drop for all in-memory credential buffers
- File permissions: 0700 dirs, 0600 files
- `exec` mode isolates credentials to child process only

See [DESIGN.md](DESIGN.md) for the full security model and threat analysis.

## Development

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

## License

[MIT](LICENSE)
