# Threat Model

This document describes the threats awsenc is designed to resist, partially
resist, or explicitly not resist.

## Assets

| Asset | Description | Sensitivity |
|---|---|---|
| AWS session credentials | AccessKeyId, SecretAccessKey, SessionToken | High -- grants AWS API access |
| Secure Enclave / TPM private key | Hardware-bound P-256 key used for ECIES encryption | Critical -- compromise enables offline cache decryption |
| Encrypted cache file | ECIES-encrypted credentials at `~/.config/awsenc/<profile>.enc` | Medium -- useless without the hardware key |
| Okta session token | Transient `/authn` session token used only during the active login flow | High -- session hijacking enables credential theft |
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
- Password prompts use `Zeroizing<String>` at input boundaries and avoid writing secrets to disk or logs.
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
- AWS credential buffers use `Zeroizing` wrappers where practical, and the decrypt-to-output window is kept short.
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

### T11: Okta session reuse (transparent reauth)

**Threat:** awsenc caches an Okta `/authn` session token alongside AWS
credentials so that `awsenc serve` can silently refresh expiring AWS creds
without prompting the user for MFA. If the cached Okta session token is
extracted, the attacker can obtain new SAML assertions and fresh AWS
credentials for the remaining Okta session lifetime (typically up to 2 hours
from the last successful MFA).

**Mitigation:**
- The Okta session token is stored only as ECIES ciphertext in the `.enc`
  cache file, encrypted under the same hardware-bound key as the AWS
  credentials (`awsenc-cli/src/auth.rs:180-199`, `serve.rs:127-204`).
  A file-level read does not reveal the session token.
- `FLAG_HAS_OKTA_SESSION` gates the behavior: profiles that do not opt into
  session reuse simply do not populate the Okta-session ciphertext field.
- Okta server-side lifetime still applies; once Okta expires the session,
  the reauth path fails over to a full `awsenc auth` prompt.
- Same hardware key / biometric posture as T6 — a same-UID attacker without
  the hardware key cannot decrypt the cached session token.

**Residual risk:** If the hardware-decrypt path is available to an attacker
(e.g. running as the user on an unlocked, non-biometric session), the cached
Okta session token enables a SAML → STS chain without re-entering MFA until
Okta's own session lifetime runs out. awsenc does not clamp session lifetime
locally — it trusts Okta's server-supplied expiration. This is the Type 1
"key accessible while session active" tradeoff, applied to Okta as well as
AWS.

### T12: SAML / STS XML parser hardening

**Threat:** Attacker-influenced SAML (via a compromised Okta or MITM of the
AppSSO flow) or STS response XML triggers XXE, billion-laughs, external
entity fetches, or decoys that smuggle alternate form fields past the
extractor.

**Mitigation:**
- SAML form extraction uses the `scraper` HTML parser with a tiered form
  selector (AWS-action form → POST+RelayState form → single-candidate form)
  at `awsenc-core/src/okta.rs`. Comment- and script-decoy tests protect
  against fake `<SAMLResponse>` injected into inert HTML.
- Decoded SAML XML is parsed by `roxmltree` — a non-validating, DTD-free,
  namespace-aware parser. XXE and DOCTYPE bombs are structurally rejected.
- STS responses are parsed by `roxmltree` via `find_text_by_local_name`
  (`awsenc-core/src/sts.rs`). No regex-based extractors remain.

**Residual risk:** A malicious form inside the SAML assertion that still
validates as an AWS sign-in form would produce attacker-chosen RoleArn /
PrincipalArn pairs, but STS enforces that the assertion is signed by a
trusted IdP so the practical impact is constrained to role selection within
the user's already-trusted Okta federation.

### T13: HTTP response size limits

**Threat:** A compromised or malicious Okta/STS endpoint streams an unbounded
response to exhaust awsenc's memory.

**Mitigation:** Both `awsenc-core/src/okta.rs` and
`awsenc-core/src/sts.rs` cap response bodies at 256 KB via
`read_response_text`. The cap is enforced **both** on the pre-fetch
`Content-Length` header **and** in the streaming loop chunk-by-chunk, so
`Transfer-Encoding: chunked` without a declared length is also bounded.

**Residual risk:** None for memory exhaustion. A truncated SAML or STS
response still fails subsequent parsing cleanly.

### T14: Local configuration file tamper

**Threat:** A same-UID attacker edits `~/.config/awsenc/config.toml` or a
profile TOML to swap `organization` (Okta origin) or `application` (SAML app
URL). On the next `awsenc auth`, the user enters their Okta password into
a prompt that identifies the correct username but POSTs credentials to a
look-alike IdP.

**Mitigation:**
- Config writes use `atomic_write` + `restrict_file_permissions` (0600) via
  `awsenc-core/src/config.rs`.
- `validate_okta_organization` enforces bare-host format but is not a
  whitelist.
- No config integrity check, no certificate pinning to a specific Okta
  tenant.

**Residual risk:** Same-UID write access is game-over for most secrets.
Documented as a trust boundary — `~/.config/awsenc/` must be protected by
OS-level file permissions and user-side hygiene.

### T15: Concurrent `awsenc serve` race

**Threat:** Two AWS CLI invocations trigger two concurrent `credential_process`
→ `awsenc serve` calls that each detect the cache in the Refresh / Expired
state. Both fire STS (and possibly the transparent reauth chain); one wins
the `atomic_write` rename, the other's work is silently discarded.

**Mitigation:** `atomic_write` ensures the cache is never partially written.

**Residual risk:** Duplicate STS/SAML traffic (minor rate-limit impact,
wasted Okta quota) and a small window where the losing writer's credentials
are returned to its caller even though they will be overwritten on the next
read. No cross-process serve lock is implemented today; adding one is a
candidate hardening. No credential leakage.

### T16: Cache rollback

**Threat:** An attacker with user-level write access replaces the current
`<profile>.enc` with an older valid ciphertext they previously exfiltrated.
The old cache is still well-formed and authenticated; awsenc serves it
until server-side STS expiration catches up.

**Mitigation:** STS credentials are short-lived (typically 1–12 hours) and
the AWS service rejects them on the server side when their own `Expiration`
passes. There is no local anti-rollback counter.

**Residual risk:** An attacker can replay an earlier intact cache for the
remainder of the STS credentials' server-side lifetime. Accepted risk;
operators needing shorter windows should shorten `DurationSeconds`.

### T17: Binary discovery / PATH hijack

**Threat:** `awsenc` invokes external helpers that are resolved via `$PATH`
(e.g. browser openers, package tools). A shim earlier on `$PATH` intercepts
the call.

**Mitigation:**
- At current code scope, `awsenc` does not shell out to `gh` / `open` /
  `$BROWSER` — the `--no-open` flow is an explicit error stub
  (`awsenc-cli/src/auth.rs:80-87`) pending Phase 6.
- The TPM bridge is discovered at a fixed path (`/mnt/c/Program Files/awsenc/`)
  rather than PATH-resolved.

**Residual risk:** If future work adds a `$BROWSER`-launch or
`open`-crate path, it must be added through `enclaveapp-core::bin_discovery`
rather than PATH.

### T18: Trusted-consumer boundary (Type 1 limit)

**Threat:** Once awsenc writes AWS credentials to the `credential_process`
stdout pipe, the consuming AWS CLI / SDK can log, persist, forward, or
exfiltrate the credentials. awsenc cannot prevent this.

**Mitigation:** None at the protocol boundary. Operators must treat the AWS
CLI (and anything they configure as `credential_process`) as a
credential-handling component.

**Residual risk:** Accepted. Type 1 integration places the consumer inside
awsenc's trusted computing base. This entry exists to make the trust
boundary explicit rather than implicit.

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
