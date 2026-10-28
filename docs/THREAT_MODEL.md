# Threat Model

This is an academic, local-first mini project. This document is deliberately explicit about
what it does and does not protect against.

## Assets

1. Plaintext file contents uploaded by users.
2. Data Encryption Keys (DEKs) — ephemeral, never persisted.
3. RSA private keys (persisted, encrypted at rest with a user passphrase).
4. Private key passphrases (never persisted).
5. User account credentials (Argon2id hashes only).
6. Classification/policy metadata and audit log entries.
7. The SQLite database and `storage/` directory contents as a whole.

## Trust assumptions

- The machine running the Streamlit app and its local filesystem are assumed to be reasonably
  trustworthy (no OS-level compromise, no malware with filesystem access). This project does
  **not** defend against a fully compromised host.
- The Python/`cryptography`/scikit-learn/argon2-cffi library implementations are trusted; this
  project implements no cryptographic primitives itself.
- Users are expected to keep their account password and RSA private-key passphrase secret and
  not reuse them elsewhere.
- This is a single-machine, localhost demonstration; it assumes no network attacker is
  positioned between the browser and the local Streamlit server (no TLS is configured here).

## Potential attackers / scenarios

| Scenario | Mitigation in this project | Residual risk |
|---|---|---|
| Attacker intercepts an `.enc` container in transit/at rest | AES-256-GCM + RSA-3072-OAEP; ciphertext is useless without the matching RSA private key and its passphrase | None known, assuming RSA-3072/AES-256 remain unbroken |
| Attacker tampers with ciphertext or container header fields | AES-GCM authentication tag covers ciphertext + AAD (header); any modification causes `InvalidTag` and decryption is refused | None for detection; does not prevent destructive tampering (overwrite), only guarantees it's detected |
| Attacker tries many passwords against a login | Argon2id hashing (slow by design) + per-account lockout after `MAX_FAILED_ATTEMPTS` | Lockout window is time-based, not permanent; a patient distributed attacker could still eventually guess a weak password — mitigated by password-strength validation |
| Attacker tries many RSA private-key passphrases | Decrypt-specific rate limiting (`src/security/authorization.py`) locks the account after repeated failures | Lockout is per-account, not per-IP; a different account is unaffected |
| A logged-in user tries to decrypt another user's file by guessing/crafting a file id or re-uploading someone else's `.enc` container | `require_file_owner` / recipient-key ownership check always queries the DB server-side using the authenticated session's user id — never a client-supplied id or filename | None for this specific attack; broader session-hijacking is out of scope (see below) |
| Attacker edits the classification field inside a container to claim it is "Public" | Classification is authenticated as AAD (tamper-evident) and, more importantly, is **never used for authorization decisions** — only ownership/key possession is | None |
| Database administrator / anyone with file-system access to `data/app.db` | Out of scope — this is a local SQLite file; OS-level access control is the only barrier | High — an attacker with filesystem access can read audit logs (no secrets, but metadata), encrypted containers, and encrypted private keys; they still cannot decrypt without the passphrase |
| Attacker steals the encrypted private-key PEM file but not the passphrase | PEM is encrypted with a PBKDF2-derived key from the passphrase | Depends entirely on passphrase strength; a weak passphrase is brute-forceable offline |
| Malicious uploaded document (e.g. PDF with embedded script, macro-laden doc) | Only read-only text extraction via `pypdf` is performed for classification preview; no macro/script execution occurs anywhere in this codebase; unsupported formats are not parsed at all | A vulnerability inside `pypdf` itself would be a supply-chain risk outside this project's control |
| Session hijacking / CSRF against the Streamlit app itself | Not specifically addressed; relies on Streamlit's own session-state isolation and running on localhost | Out of scope for this academic MVP; a production deployment would need TLS, proper session cookie hardening, and reverse-proxy protections |
| Timing/enumeration attack to learn whether a username exists | Login performs a decoy hash verification when the username is not found, to reduce (not eliminate) timing signal | Residual timing differences are plausible under careful measurement |

## Mitigations summary

- AES-256-GCM (authenticated encryption) for all file content; RSA-3072-OAEP-SHA256 for key
  wrapping — both via the maintained `cryptography` library, no custom crypto.
- Argon2id for password hashing (`argon2-cffi`), passphrase-based PEM encryption for private
  keys (PBKDF2-backed `BestAvailableEncryption`).
- Fail-closed authorization: ownership is always re-derived server-side from the session's
  user id; classification/claimed identity in client-supplied data is never trusted for access
  decisions.
- Fail-closed decryption: no plaintext (partial or complete) is ever returned before the
  AES-GCM tag verifies.
- Rate limiting / lockout on both login and decryption attempts.
- Privacy-conscious audit logging: no plaintext, passwords, passphrases, private keys, or DEKs
  are ever written to the log (enforced by code review and a regression test,
  `tests/test_app_infra.py::test_audit_log_never_contains_password_field`).

## Explicit limitations / residual risks

- **Not tamper-proof logging.** The audit log is an ordinary SQLite table. Anyone with direct
  database write access can alter or delete past rows undetected. A production system would
  need append-only/WORM storage, log signing, or an external SIEM.
- **No secure deletion guarantee.** Removing a file record or the underlying `.enc` file does
  not guarantee the bytes are unrecoverable from disk, SSD wear-leveled flash, OS file-system
  journals, or any backups.
- **Owner-only decryption (MVP scope).** Multi-recipient sharing is not implemented; a full
  implementation would need an explicit per-recipient key-wrapping workflow (wrap the same DEK
  for each recipient's public key) rather than sharing one user's private key — documented here
  as a known, deliberate scope limitation.
- **Small, synthetic ML training set.** The classifier is real and functional but trained on a
  few dozen synthetic examples; it is not validated for production-grade accuracy and should
  not be relied upon as the sole safeguard for real sensitive data.
- **No network-layer hardening.** This app is designed to run on `localhost` for demonstration;
  it does not configure TLS, CSRF protection, or rate limiting at the network layer.
- **No defense against a fully compromised host.** If the machine itself is compromised (e.g.
  keylogger, memory scraper), passphrases and plaintext can be captured regardless of any
  control described above.
- **No claim of perfect or unbreakable security.** This project demonstrates sound use of
  established cryptographic constructions; it does not claim invulnerability.
