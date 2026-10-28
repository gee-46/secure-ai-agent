# Architecture

## Component overview

```
app.py (Streamlit UI — no crypto/auth logic itself)
  |
  +-- src/auth       -> registration, login, Argon2id hashing, lockout
  +-- src/ai         -> classifier (TF-IDF+LogReg), pattern rules, policy engine, text extraction
  +-- src/crypto     -> container format, hybrid AES-GCM/RSA-OAEP engine, RSA key generation
  +-- src/security   -> authorization (ownership checks), decrypt rate limiting
  +-- src/storage    -> SQLite schema/connections, repository queries, safe file I/O
  +-- src/audit      -> structured, privacy-conscious audit logging
  +-- src/utils      -> config loading, input validation/sanitization, UI theme
```

Design rule: **UI code never performs cryptography or authorization decisions directly** — it
only calls into `src/crypto`, `src/security`, and `src/auth`, and only acts on their results.

## Data flow: encryption

1. User uploads a file (Streamlit `file_uploader`); the browser-side filename is sanitized
   (`src/utils/validation.sanitize_display_filename`) and the size is checked against
   `MAX_UPLOAD_MB`. The original filename/path is **never** used as a filesystem path.
2. `src/ai/text_extraction.py` extracts text from supported formats only (`.txt`, `.md`, `.csv`,
   `.pdf`). Unsupported/binary files are not decoded as text — they are still encrypted as raw
   bytes, with manual classification review.
3. `src/ai/classifier.py` runs the local TF-IDF+LogisticRegression pipeline (or a conservative
   rule-only fallback if the model file is missing) and combines it with
   `src/ai/patterns.py` regex detectors. Pattern matches can only **escalate** the required
   classification floor, never lower it.
4. `src/ai/policy.py` deterministically maps the (possibly user-overridden) classification to a
   `SecurityPolicy`. Every policy requires AES-256-GCM + RSA-OAEP, regardless of label.
5. `src/crypto/hybrid.encrypt_file`:
   - Generates a fresh 256-bit DEK (`os.urandom(32)`) and a fresh 96-bit nonce
     (`os.urandom(12)`) — unique per encryption call.
   - Builds a `ContainerHeader` (format version, algorithm identifiers, recipient key id,
     classification, policy, display name) and serializes it canonically as AES-GCM AAD, so
     tampering with any of those fields is detected at decrypt time.
   - Encrypts the plaintext with `AESGCM(dek).encrypt(nonce, plaintext, aad)`.
   - Wraps the DEK with the recipient's RSA-3072 public key using OAEP(SHA-256).
   - Serializes header + nonce + wrapped DEK + ciphertext as a versioned JSON container
     (`src/crypto/container.py`), Base64-encoding all binary fields.
6. `src/storage/file_store.save_container` writes the container under a fresh internal UUID
   (never a user-supplied name) using write-to-temp-then-`os.replace` for atomicity.
7. `src/storage/repository.create_file_record` stores the file's metadata (owner, classification,
   policy, recipient key id, path) in SQLite.
8. `src/audit/audit_log.record_event` logs `CLASSIFICATION`, `POLICY_DECISION`, and
   `ENCRYPT_SUCCESS` events (safe metadata only).

## Data flow: decryption

1. The current session's authenticated user id is used — never a filename or a claimed user id.
2. `src/security/authorization.check_decrypt_rate_limit` fails closed if the account is
   temporarily locked out from repeated failed decrypt attempts.
3. For a file selected from "My encrypted files": `require_file_owner(user_id, file_id)` looks
   up the DB record and raises `AuthorizationError` unless `owner_user_id == user_id`.
   For an uploaded `.enc` container (no DB file_id): the container's `recipient_key_id` is looked
   up in `key_pairs`, and `AuthorizationError` is raised unless that key's `owner_user_id` is the
   current session user. **The classification embedded in the container is never trusted for
   this decision.**
4. The container is validated (`deserialize_container`): JSON structure, required fields,
   supported format version, Base64 validity, minimum nonce/ciphertext lengths. Malformed input
   raises `ContainerFormatError` before any cryptographic operation runs.
5. The RSA private key is loaded from its encrypted PEM using the user-supplied passphrase
   (`src/crypto/keys.load_private_key`); a wrong passphrase raises `KeyError_` without revealing
   which part was wrong.
6. The DEK is unwrapped with RSA-OAEP; any unwrap failure raises `DecryptionError` with a
   generic message.
7. `AESGCM(dek).decrypt(nonce, ciphertext, aad)` verifies the authentication tag against both
   the ciphertext **and** the header AAD before returning plaintext. On `InvalidTag`, a
   `DecryptionError` is raised and **no plaintext is ever returned** — decrypt-then-verify is
   not used anywhere in this codebase.
8. On success: `record_decrypt_success` resets the lockout counter, an `DECRYPT_SUCCESS` audit
   event is recorded, and the plaintext is offered to the browser via `st.download_button`
   (never silently written to a shared directory on disk).
9. On any failure: `record_decrypt_failure` increments the lockout counter and a
   `DECRYPT_DENIED` or `INTEGRITY_FAILURE` audit event is recorded with safe metadata only.

## Key lifecycle

1. **Generation** (`src/crypto/keys.generate_rsa_keypair`): RSA-3072 key pair generated with
   the `cryptography` library (no custom primitives).
2. **Private key protection**: the private key is serialized as PKCS8 PEM and encrypted with
   `serialization.BestAvailableEncryption(passphrase)` (PBKDF2-backed). The passphrase itself is
   never persisted or logged anywhere.
3. **Storage**: public PEM and encrypted private PEM are written to `storage/keys/` under a
   fresh UUID (`file_store.save_key_material`), separate from encrypted document storage.
   A `key_pairs` DB row links the key id to its owning user and file paths.
4. **Use (encrypt)**: only the public PEM is loaded into memory to wrap a DEK.
5. **Use (decrypt)**: the encrypted private PEM is loaded and decrypted in-memory with the
   user-supplied passphrase, used once to unwrap a DEK, and not persisted elsewhere.
6. **Loss**: if the private key file or its passphrase is lost, any data encrypted for that key
   is **permanently unrecoverable** — there is no key-recovery mechanism, by design.

## Trust boundaries

- **Browser ↔ Streamlit server**: Streamlit's session state is server-side per browser session;
  this project does not add extra transport security beyond what you run it behind (e.g. for a
  real deployment you would terminate TLS in front of Streamlit — out of scope for this
  localhost academic demo).
- **Application ↔ SQLite file**: trusted as the application's only persistent store; anyone
  with OS-level read/write access to `data/app.db` or `storage/` bypasses the application layer
  entirely (see `docs/THREAT_MODEL.md`).
- **Uploaded documents**: always treated as untrusted bytes. No embedded script/macro content
  is ever executed; only safe, read-only text extraction is performed for supported formats.

## Failure handling

Every cryptographic and authorization failure in this codebase **fails closed**: no plaintext,
partial plaintext, key material, or passphrase is ever returned, logged, or displayed on error.
User-facing error messages are generic by design (e.g. "the file could not be authenticated");
the specific internal exception types (`DecryptionError`, `AuthorizationError`, `KeyError_`,
`ContainerFormatError`, `RateLimitError`) are used internally for correct audit categorization
only.
