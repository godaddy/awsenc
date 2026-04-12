# Threat Model

This document describes the threats awsenc is designed to resist, partially
resist, or explicitly not resist.

## Assets

| Asset | Description | Sensitivity |
|---|---|---|
| AWS session credentials | AccessKeyId, SecretAccessKey, SessionToken | High -- grants AWS API access |
| Secure Enclave / TPM private key | Hardware-bound P-256 key used for ECIES encryption | Critical -- compromise enables offline cache decryption |
| Encrypted cache file | ECIES-encrypted credentials at `~/.config/awsenc/<profile>.enc` | Medium -- useless without the hardware key |
| Okta session token | Cached Okta session used to obtain new SAML assertions | High -- session hijacking enables credential theft |
| SAML assertion | Signed XML from Okta authorizing AWS role assumption | High -- short-lived but grants STS access |
| Okta password | User's Okta credentials entered during authentication | Critical -- entered interactively, never stored |
| Configuration files | TOML files with Okta org, application URL, role ARN | Low -- no secrets, controls behavior |

## Trust Boundaries

```
+-------------------------------------------------------------------+
| User's Machine                                                     |
|                                                                    |
|  +-----------------+    +----------------+    +-----------------+  |
|  | AWS CLI / SDK   |    | awsenc binary  |    | Secure Enclave  |  |
|  | (consumer)      |<-->| (Rust process) |<-->| / TPM           |  |
|  +-----------------+    +-------+--------+    +-----------------+  |
|                                 |                                  |
|                   credential_process                               |
|                                 |                                  |
|                    +------------+------------+                     |
|                    |                         |                     |
|             +------+------+          +-------+------+             |
|             | Okta IdP    |          | AWS STS      |             |
|             | (SAML)      |          | (AssumeRole) |             |
|             +-------------+          +--------------+             |
+-------------------------------------------------------------------+
```

**Trust boundaries:**
1. Between awsenc and the hardware security module (SE/TPM).
2. Between awsenc and Okta (HTTPS, user authenticates with MFA).
3. Between awsenc and AWS STS (HTTPS, SAML assertion).
4. Between awsenc and the AWS CLI (credential_process JSON on stdout).
5. Between the user's machine and external attackers (disk, network, physical).

## Threats and Mitigations

### T1: Plaintext credentials on disk

**Threat:** An attacker with read access to the user's home directory reads
cached AWS credentials from plaintext files.

**Previous state:** `aws-okta-processor` caches credentials as plaintext.
`~/.aws/credentials` stores long-lived keys in plaintext.

**Mitigation:** Cached credentials are encrypted with ECIES using a P-256
key pair generated in the Secure Enclave (macOS) or TPM 2.0 (Windows).
The private key never leaves the hardware.

**Residual risk:** None for the cached credentials. Credentials briefly
exist in process memory as plaintext during the decrypt-to-output path.

### T2: Ambient environment variable exposure

**Threat:** A developer runs `export AWS_ACCESS_KEY_ID=...`, persisting
credentials in the shell environment where every child process inherits them.

**Mitigation:**
- `credential_process` integration means the AWS CLI fetches credentials on
  demand. No environment variables are set.
- Shell integration (`eval "$(awsenc shell-init)"`) detects `export` of
  AWS credential variables and warns.
- `exec` mode injects credentials directly into the child process environment
  without touching the parent shell.

**Residual risk:** Users can still manually export credentials. The shell
wrapper is best-effort and can be bypassed.

### T3: Cross-machine replay of stolen cache

**Threat:** An attacker copies the `.enc` cache file to another machine and
decrypts it.

**Mitigation:** The encryption key is hardware-bound (Secure Enclave / TPM).
It is non-exportable and tied to the physical device.

**Residual risk:** None. The hardware provides this guarantee.

### T4: Okta credential interception

**Threat:** An attacker intercepts the Okta password or MFA response during
authentication.

**Mitigation:**
- All Okta communication uses HTTPS with rustls (TLS 1.2/1.3).
- Passwords are read from the terminal with echo disabled.
- Passwords are held in `Zeroizing` buffers and wiped after use.
- MFA factors (YubiKey OTP, push, TOTP) provide second-factor protection.

**Residual risk:** A compromised CA could issue fraudulent certificates.
A keylogger could capture the password before it reaches awsenc.

### T5: SAML assertion theft

**Threat:** An attacker intercepts the SAML assertion between Okta and
awsenc, or between awsenc and AWS STS.

**Mitigation:**
- SAML assertions are fetched over HTTPS and used immediately.
- Assertions are short-lived (typically 5 minutes).
- Assertions are not written to disk or logged.

**Residual risk:** An attacker with process memory access could extract
the assertion during the brief window between receipt and STS call.

### T6: Root/admin access on active session

**Threat:** An attacker with root access calls SE/TPM APIs to decrypt
cached credentials.

**Mitigation:**
- The `--biometric` option requires Touch ID / Windows Hello for each
  decryption, adding a physical-presence check.
- Without biometric: the key is accessible to any process running as the
  user when the device is unlocked.

**Residual risk:** Root can install keyloggers, modify the binary, or
intercept credentials in other ways. Hardware security modules protect
against offline attacks, not a fully compromised running system.

### T7: Process memory extraction

**Threat:** An attacker with root or ptrace access reads credentials from
awsenc's process memory.

**Mitigation:**
- Credential buffers use `Zeroizing<Vec<u8>>` which overwrites on drop.
- The window of exposure is minimized: credentials exist in plaintext only
  during the decrypt-to-output path.

**Residual risk:** Between decryption and stdout output, credentials are
in process memory. This is inherent to any credential passing scheme.

### T8: Encrypted cache tampering

**Threat:** An attacker modifies the `.enc` cache file to extend credential
validity or alter cached data.

**Mitigation:**
- ECIES ciphertext includes an AES-GCM authentication tag. Tampering with
  the ciphertext causes decryption failure.
- The unencrypted cache header (expiration timestamps) controls client-side
  caching only. AWS STS enforces its own credential expiration independently.

**Residual risk:** Header tampering can extend client-side caching but
cannot create valid AWS credentials or extend their server-side validity.

### T9: WSL bridge compromise

**Threat:** An attacker replaces `awsenc-tpm-bridge.exe` with a malicious
binary that returns fake credentials or steals them.

**Mitigation:**
- The bridge path points to `Program Files` which requires admin rights
  to modify on Windows.
- The bridge is distributed alongside the main installer.

**Residual risk:** An attacker with admin rights on the Windows host could
replace the bridge binary. But an attacker with admin rights already
controls the TPM.

### T10: Software fallback weakness (Linux)

**Threat:** On Linux without TPM, the software fallback provides file-based
encryption only. A compromised user session can extract credentials.

**Mitigation:**
- A one-time warning is printed when the software backend is used.
- File permissions restrict access to the owning user.
- This is documented as the weakest backend.

**Residual risk:** Any process running as the user can access the
encryption key. This is a known limitation.

### T11: Okta session reuse

**Threat:** A cached Okta session token is used by an attacker to obtain
new SAML assertions without MFA.

**Mitigation:**
- Okta session tokens are encrypted with the same hardware-bound key as
  AWS credentials.
- Sessions have a limited lifetime (typically 2 hours).
- Destroying the cache (`awsenc clear`) immediately invalidates the
  local session.

**Residual risk:** Within the session window, anyone who can decrypt the
cache can obtain new SAML assertions. The `--biometric` option mitigates
this by requiring physical presence for decryption.

## Out of Scope

- **Physical attacks on the Secure Enclave or TPM hardware.** We rely on
  Apple's and Microsoft's hardware security guarantees.
- **Kernel exploits.** A kernel-level compromise can bypass all software
  protections.
- **Okta or AWS service compromise.** Server-side vulnerabilities are
  outside awsenc's control.
- **Supply chain attacks on awsenc itself.** Standard open-source mitigation
  (reproducible builds, signed releases) applies.
- **Denial of service.** An attacker who can delete cache files can force
  re-authentication but cannot access credentials.
