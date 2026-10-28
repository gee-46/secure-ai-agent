# Viva Questions and Answers

### 1. What is the difference between symmetric and asymmetric encryption?
Symmetric encryption uses the *same* key to encrypt and decrypt (fast, used here for bulk data
via AES-256-GCM). Asymmetric encryption uses a *key pair* — a public key for encryption and a
private key for decryption (slower, used here only to wrap a small 256-bit key via RSA-OAEP).

### 2. What is hybrid encryption, and why use it here?
Hybrid encryption combines symmetric and asymmetric encryption: a fresh symmetric key (the DEK)
encrypts the actual data efficiently, and that small DEK is then encrypted ("wrapped") with the
recipient's RSA public key. This gets AES's speed for large data and RSA's key-distribution
convenience, without RSA's poor performance on large payloads.

### 3. Why AES-256-GCM specifically, instead of plain AES-CBC?
GCM is an *authenticated* encryption mode: it produces a ciphertext and an authentication tag
that together prove the ciphertext (and any associated data) was not modified. Plain CBC gives
no integrity guarantee by itself and is vulnerable to padding-oracle-style attacks if not paired
with a separate MAC.

### 4. What is a nonce, and why must it be unique per AES-GCM key?
A nonce ("number used once") is a 96-bit value fed into AES-GCM alongside the key. Reusing a
nonce with the same key catastrophically breaks GCM's confidentiality and authenticity
guarantees (it allows forging valid ciphertexts/tags). This project generates a fresh
cryptographically random nonce (`os.urandom(12)`) for every single encryption call.

### 5. What is the authentication tag in AES-GCM?
A value computed over the ciphertext and any associated authenticated data (AAD) that lets the
decrypting party verify nothing was altered. If verification fails, `cryptography` raises
`InvalidTag` and this project refuses to return any plaintext at all.

### 6. What is AAD (Associated Authenticated Data), and what do you authenticate as AAD here?
AAD is data that is authenticated but not encrypted. This project authenticates the container's
header metadata (format version, algorithm identifiers, recipient key id, classification,
policy name, display name) as AAD, so an attacker cannot silently change, e.g., the recorded
classification or recipient without the tampering being detected at decrypt time.

### 7. What is RSA-OAEP, and why not "textbook" RSA?
OAEP (Optimal Asymmetric Encryption Padding, RFC 8017) is a padding scheme that makes RSA
encryption secure against chosen-ciphertext attacks and ensures ciphertexts are
indistinguishable from random. "Textbook" RSA without proper padding is deterministic and
insecure for general use.

### 8. Why RSA-3072 instead of RSA-2048 or RSA-4096?
RSA-3072 offers a security strength roughly comparable to AES-128 (~128-bit security), a solid
modern baseline that exceeds 2048-bit (now considered a longer-term risk) while avoiding
4096-bit's extra computational cost, for an academic project where keys aren't rotated at scale.

### 9. What is a Data Encryption Key (DEK) and why generate a new one per file?
The DEK is the random, ephemeral AES-256 key that directly encrypts a file's content. Generating
a fresh DEK per file limits the blast radius of any single key's compromise to just that one
file, and avoids any nonce-reuse risk across files sharing a key.

### 10. How is the RSA private key protected at rest?
It's serialized as PKCS8 PEM and encrypted using the `cryptography` library's
`BestAvailableEncryption`, which derives a key-encryption key from a user-supplied passphrase
(PBKDF2-backed). The plaintext private key is never written to disk, logged, or displayed.

### 11. What happens if a user loses their private key or passphrase?
The encrypted file(s) wrapped for that key become permanently unrecoverable — there is no
password-reset or key-recovery mechanism, by design, since any recovery backdoor would itself
be a security weakness.

### 12. Why use Argon2id instead of bcrypt or plain SHA-256 for passwords?
Argon2id is the winner of the Password Hashing Competition and is memory-hard, making it
resistant to GPU/ASIC-accelerated brute-force attacks. Plain SHA-256 is fast and *unsalted by
default*, making it unsuitable for password storage; bcrypt is reasonable but lacks Argon2's
tunable memory-hardness.

### 13. How does the system detect repeated failed login attempts?
Each account tracks `failed_attempts` and a `locked_until` timestamp in the `users` table. After
`MAX_FAILED_ATTEMPTS` consecutive failures, the account is locked for `LOCKOUT_SECONDS`, even if
the next attempt uses the correct password.

### 14. How is decryption authorization enforced — can a user just change a filename or user ID to get access?
No. Authorization always re-derives ownership server-side: for a file stored by the app,
`require_file_owner` queries the `files` table using the *session's authenticated* user id; for
an uploaded container, the app looks up the container's `recipient_key_id` in the `key_pairs`
table and checks that *that* key's owner matches the session user. Nothing client-supplied
(filename, embedded classification, a claimed user id) is ever trusted for this decision.

### 15. Why doesn't the AI classifier's prediction affect who can decrypt a file?
Because ML predictions can be wrong, biased, or adversarially manipulated (e.g., crafted input
that causes misclassification). Using an AI output as an access-control gate would let an
attacker potentially bypass security by manipulating the classifier. Here, classification only
ever influences a *recommended policy*, and policies only ever add requirements, never grant
access or weaken cryptography.

### 16. How does the application combine the ML model with rule-based detection?
`src/ai/patterns.py` applies deterministic regex rules (emails, phone numbers, account-like
IDs, financial/medical/credential keywords) to compute a minimum classification "floor". If the
ML model's prediction is *less* sensitive than that floor, the final classification is escalated
to the floor — rules can only make the outcome more conservative, never less.

### 17. What happens if the ML model file is missing or fails to load?
The classifier falls back to a rule-only mode: if any sensitive pattern matches, the floor label
is used; otherwise it defaults to "Confidential" (never silently defaults to "Public" without a
trained model), and the result is flagged `model_available=False` with a low-confidence warning.

### 18. How is classifier confidence surfaced to the user?
`predict_proba` returns per-class probabilities; the top class's probability is compared to a
fixed `LOW_CONFIDENCE_THRESHOLD` (0.5). Below that, the UI displays an explicit low-confidence
warning recommending manual review.

### 19. What does "explainable AI" mean in this project, concretely?
Two things: (1) the regex pattern matches are shown by name (e.g. `email_address`,
`credential_keyword`) so the user sees exactly which signal fired; (2) for ML-driven
predictions, the logistic regression's learned coefficients for the predicted class are used to
surface the input's most positively-weighted terms ("influential terms").

### 20. Can a user override the AI's classification? Does that weaken security?
Yes, with a required justification, logged as a `POLICY_DECISION` audit event. It does not
weaken security because the policy mapping and the authentication/authorization pipeline are
unaffected by the label — overriding only changes which *recommended* policy tier is applied,
and even "Public" still requires authenticated encryption and authorized decryption.

### 21. What is the versioned container format, and why version it?
It's a JSON document with a `format_version` integer, algorithm identifiers, the nonce, the
RSA-wrapped DEK, and the AES-GCM ciphertext (all binary fields Base64-encoded). Versioning lets
the decrypt path explicitly reject any format it doesn't recognize
(`ContainerFormatError: Unsupported container format version`) instead of guessing, which is
safer than silently trying to parse an unknown structure.

### 22. How does the system prevent path traversal or unsafe file handling?
Uploaded filenames are sanitized to a safe display-only string (`sanitize_display_filename`,
which strips directory components and unsafe characters) and are never used as an actual
filesystem path. All stored files (encrypted containers and key material) are written under
fresh server-generated UUIDs inside managed directories, and read-back paths are validated to
stay within those managed directories before any read.

### 23. Why are writes to storage done "atomically" (temp file + rename)?
To avoid leaving a half-written, corrupted file on disk if the process crashes or is
interrupted mid-write; `os.replace` is atomic on both POSIX and Windows for files on the same
volume.

### 24. What does the audit log capture, and what does it deliberately exclude?
It captures timestamps, the authenticated user id/username, event type (e.g.
`ENCRYPT_SUCCESS`, `DECRYPT_DENIED`, `INTEGRITY_FAILURE`), the related file id, a status, and a
short safe "detail" string. It never logs plaintext content, passwords, passphrases, private
keys, or DEKs — enforced both by code convention and a regression test that statically scans
the audit module's source for those terms.

### 25. Is the audit log tamper-proof?
No — it's an ordinary SQLite table. Anyone with direct filesystem/database access to
`data/app.db` could alter past rows. This is explicitly documented as a limitation in
`docs/THREAT_MODEL.md`; a production system would need append-only or cryptographically signed
logging for tamper-evidence.

### 26. How would you add support for sharing an encrypted file with a second user?
By wrapping the *same* DEK a second time under the second recipient's RSA public key and storing
a second "grant" record (recipient key id → wrapped DEK) rather than sharing the first user's
private key. This project documents that as a scope limitation rather than implementing it, to
keep the MVP's authorization model simple and auditable.

### 27. What would you change before using this in a real production environment?
Add TLS/reverse-proxy deployment, tamper-evident/append-only audit logging, a much larger and
properly vetted training dataset with ongoing accuracy monitoring, hardware-backed or HSM/KMS
key storage instead of passphrase-encrypted PEM files, and formal secure-deletion/retention
policies — all explicitly called out in `docs/THREAT_MODEL.md`.

### 28. Why is empty-file encryption/decryption tested?
To confirm AES-GCM correctly handles a zero-length plaintext (it does — the ciphertext is just
the authentication tag) and that the round trip doesn't crash on an edge case that's easy to
mishandle in custom code (which is exactly why this project avoids custom cryptographic code).
