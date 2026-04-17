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

**Threat:** An attacker modifies the `.enc` cache file (header fields or
ciphertext) to extend credential validity or replay an older cached
credential.

**Mitigation:**
- ECIES ciphertext includes an AES-GCM authentication tag. Tampering
  with the ciphertext causes decryption failure.
- The previously-unauthenticated header (magic, version, flags,
  credential expiration, Okta session expiration) is now bound into
  the encrypted envelope via `awsenc_core::cache::wrap_for_encrypt` /
  `unwrap_after_decrypt`. The envelope format is
  `[4B "APL1"][32B SHA-256(header bytes)][8B u64 counter][payload]`
  (`crates/enclaveapp-cache/src/envelope.rs`). Any edit to header
  fields after encrypt is detected as a hash mismatch and the decrypt
  result is rejected before bytes cross the caller boundary.
- AWS STS enforces its own credential expiration independently;
  server-side `exp` is the ultimate authority on credential validity.

**Residual risk:** Header tampering alone can no longer extend
client-side caching; it instead surfaces as a decrypt error. Replay of
an older still-valid ciphertext is addressed by T16 below.

### T9: WSL bridge compromise

**Threat:** An attacker replaces `awsenc-tpm-bridge.exe` with a malicious
binary that returns fake credentials or steals them.

**Mitigation:**
- The bridge path points to `Program Files` which requires admin rights
  to modify on Windows.
- The bridge client (`crates/enclaveapp-bridge/src/client.rs`) no longer
  has a `which`-based PATH fallback — discovery is restricted to fixed
  admin install paths plus the `ENCLAVEAPP_BRIDGE_PATH`
  (or `{APP}_BRIDGE_PATH`) env-var override.
- Before spawn, `require_bridge_is_authenticode_signed` parses the PE
  header's `IMAGE_DIRECTORY_ENTRY_SECURITY` directory and refuses
  binaries with no Authenticode signature block. Blocks the
  "attacker compiled their own unsigned bridge" case.
- The bridge is distributed alongside the main installer.

**Residual risk:** An attacker with Windows admin rights can still
replace the bridge with a validly-signed-but-malicious binary; full
`WinVerifyTrust` chain verification is not reachable from the WSL
side. An attacker with admin rights already controls the TPM anyway.

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
state. Both would otherwise fire STS (and possibly the transparent-reauth
chain); one wins the `atomic_write` rename, the other's work is silently
discarded.

**Mitigation:**
- `awsenc serve` acquires an exclusive `fs4` advisory lock on
  `<profile>.enc.lock` before touching the cache
  (`awsenc-cli/src/serve.rs::ServeLock`). The second caller blocks
  until the first releases, then reads the now-fresh cache.
- `atomic_write` ensures the cache file is never partially written.

**Residual risk:** None for credential leakage. The lock file itself
is empty and per-profile; a concurrent removal is benign (the next
call re-creates it). Cross-host concurrent serve (e.g. NFS home dir)
is advisory-only — documented as unsupported.

### T16: Cache rollback

**Threat:** An attacker with user-level write access replaces the current
`<profile>.enc` with an older valid ciphertext they previously exfiltrated.
Before the monotonic counter landed, the old cache would be served until
server-side STS expiration caught up.

**Mitigation:**
- The encrypted envelope
  (`crates/enclaveapp-cache/src/envelope.rs`) embeds an 8-byte big-endian
  monotonic counter in the plaintext before AES-GCM encryption. The
  counter is bumped on every successful write and persisted in a
  `<profile>.enc.counter` sidecar, protected by an exclusive `fs4`
  flock. On decrypt, the embedded counter is compared against the
  sidecar; if it is strictly less, the load is rejected as `Rollback
  { observed, expected_at_least }`.
- STS `Expiration` on the server side remains authoritative, so even
  a successful rollback within the counter window still expires at
  the real AWS deadline.

**Residual risk:** An attacker who writes BOTH the stale `.enc` and
the sidecar back simultaneously (or who rolled back the whole
filesystem snapshot) can still replay within the server-side
validity window. The sidecar is same-UID-writable by design; that's
a generic same-UID-compromise risk shared with config files.
Deletion of the sidecar alone does not help — `next_counter` seeds
from the highest counter observed in any successfully-decrypted
ciphertext, so forward progress is preserved after a delete + re-read
cycle. Operators needing tighter bounds should shorten
`DurationSeconds`.

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
