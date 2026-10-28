# Test Results (actually executed)

All commands below were run locally in a Python 3.13.7 virtual environment on Windows, from the
project root, with dependencies from `requirements.txt` installed. Output is reproduced
verbatim (trimmed only where noted). No results in this document are invented.

## 1. Classifier training

Command:
```
python scripts/train_classifier.py
```

Observed output:
```
=== Held-out evaluation (small synthetic dataset; not production accuracy) ===
                     precision    recall  f1-score   support

       Confidential       1.00      0.67      0.80         3
Highly Confidential       0.75      1.00      0.86         3
             Public       0.67      0.67      0.67         3

           accuracy                           0.78
          macro avg       0.81      0.78      0.77         9
       weighted avg       0.81      0.78      0.77         9

Model saved to: <project>/models/sensitivity_classifier.joblib
```

This is a held-out evaluation on **9 synthetic examples** (25% of a 36-example dataset). It
demonstrates the pipeline trains and evaluates correctly; it is explicitly **not** a claim of
production-grade accuracy (see `docs/PROJECT_REPORT.md` and `docs/THREAT_MODEL.md`).

## 2. Automated test suite (pytest)

Command:
```
python -m pytest tests/ -v
```

Observed output (final summary line, full per-test results were all `PASSED`):
```
52 passed in 16.68s
```

Full list of executed tests (all PASSED):

**Cryptography (`tests/test_crypto.py`)** (18 tests) — round-trip text, binary, empty file, large file
(5 MB), unique nonce/DEK per encryption, wrong passphrase rejected, wrong private key rejected,
tampered ciphertext detected, tampered nonce detected, tampered authenticated metadata
detected, corrupted wrapped DEK detected, truncated container rejected, malformed container
rejected, unsupported format version rejected, empty container rejected, unsupported AES algorithm
rejected, unsupported RSA algorithm rejected, invalid wrapped DEK length rejected.

**Authentication (`tests/test_auth.py`)** (7 tests) — register and login success, duplicate registration
rejected, wrong password rejected, unknown user rejected, weak password rejected, account
lockout after repeated failures (and unlock after the lockout window), password never stored in
plaintext (verified Argon2id hash prefix `$argon2id$`).

**Authorization (`tests/test_authorization.py`)** (4 tests) — owner can access own file, other user
cannot access file, nonexistent file rejected, decrypt rate limiting (lockout + recovery).

**AI classification (`tests/test_ai_classifier.py`)** (9 tests) — public example classification, email
pattern detection, highly-confidential rule escalation, credential-keyword forced escalation,
missing-model conservative fallback, empty-text conservative default, low-confidence flag
present, rule-based floor detection (phone + email), no floor for clean text.

**Text extraction (`tests/test_text_extraction.py`)** (3 tests) — plain text extraction, unsupported
binary extension rejected, invalid UTF-8 text rejected.

**Application infrastructure (`tests/test_app_infra.py`)** (11 tests) — database tables exist,
registration creates a user row, audit event recorded and queryable, audit module source
contains no banned sensitive references outside its docstring, filename sanitization strips path
traversal, upload-size validation (accepts in-range, rejects oversized/empty), username validation
rejects invalid characters, key material storage rejects path traversal identifiers, key material
loading strictly checks managed directory boundaries, container loading rejects traversal paths,
audit logging automatically redacts sensitive substrings from detail strings.

## 3. Live end-to-end application run

The real `app.py` was launched with Streamlit and confirmed to serve HTTP 200:
```
streamlit run app.py --server.headless true --server.port 8765
...
HTTP_STATUS:200
```

A scripted run using Streamlit's `AppTest` framework (against an isolated temporary database,
never the developer database) then drove the actual UI code paths:

```
1. App loaded (login screen) OK
2. Registration OK -> ["Account created. Please log in from the 'Log in' tab."]
3. Login OK, session user: faculty_demo
4. Key pair generated: ["Key pair 'integration-test-key' generated (RSA-3072, OAEP-SHA256). Key ID: `3645a74e92d9442dbd9a2a4dc993804a`."]
5. Key pair persisted in DB: 3645a74e92d9442dbd9a2a4dc993804a
6. Encrypted via backend wiring, classification: Highly Confidential -> policy: Strict
7. Decrypted successfully, bytes match original exactly. Header classification: Highly Confidential
8. Wrong passphrase correctly rejected
9. Cross-user access correctly denied
10. Tampered ciphertext correctly rejected (no partial plaintext released)

ALL APPTEST + BACKEND WORKFLOW STEPS PASSED
```

Step 6 onward exercises the exact same backend functions (`src/crypto/hybrid.py`,
`src/security/authorization.py`, `src/storage/*`) that `app.py`'s "Encrypt Files" and "Decrypt
Files" pages call, confirming the full register → login → generate key → classify → encrypt →
decrypt workflow — plus three negative security scenarios (wrong passphrase, cross-user denial,
tampered ciphertext) — all behave as designed through the real application code.

## Known non-issues observed during testing

- Two early test-suite failures were found and fixed during development, not hidden:
  1. `create_file_record` originally generated its own internal file id instead of reusing the
     id under which the container was physically saved, breaking the DB-to-file link used by
     `require_file_owner`. Fixed by passing the storage-assigned id through explicitly.
  2. `login_user`'s account-lockout write was being silently rolled back because it was
     committed via a context manager that only commits on the *non-exception* path, while the
     lockout code path always raises `AuthError` immediately after writing. Fixed by committing
     explicitly before raising.

Both are called out here for transparency about the actual development/debugging process.
