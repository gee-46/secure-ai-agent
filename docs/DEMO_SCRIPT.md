# Demo Script (5–8 minutes)

## One-line pitch for faculty

"This is a local, offline application that uses a small explainable AI model to suggest how
sensitive a document is, then actually encrypts it with industry-standard hybrid cryptography
(AES-256-GCM + RSA-OAEP) — and the AI's suggestion never controls who can decrypt it; that's
always enforced by login and file ownership, checked on the server side."

## Setup (before the audience arrives)

```bash
cd privacy-preserving-ai-agent
.venv\Scripts\activate           # or: source .venv/bin/activate
python scripts/initialize_db.py  # if not already done
python scripts/train_classifier.py
streamlit run app.py
```

Have a short confidential-sounding `.txt` file ready (e.g. containing an email address and the
word "invoice"), and a plain public-sounding one.

## Sequence

1. **(30s) Register / log in.** Show the "Register" tab, create an account, then log in.
   *Say:* "Passwords are hashed with Argon2id — never stored in plaintext."

2. **(60s) Key Management.** Generate an RSA-3072 key pair with a passphrase.
   *Say:* "This is the recipient key pair. The private key is encrypted at rest with this
   passphrase — if I lose either the key file or the passphrase, anything encrypted for this
   key is gone forever, there's no backdoor."
   *Expected result:* success message with a key id; download buttons appear for the public key
   and the encrypted private key backup.

3. **(60s) AI Security Analysis.** Paste a sentence containing an email address and the word
   "invoice" (e.g. *"Please send the invoice to john.doe@example.com before Friday."*).
   *Expected result:* predicted classification (likely "Confidential"), a bar chart of class
   probabilities, and matched indicators like `email_address`. Show the recommended policy and
   its listed reasons.

4. **(90s) Encrypt Files.** Upload the confidential-sounding `.txt` file.
   *Expected result:* AI suggestion + policy shown again; select/confirm the classification;
   pick the RSA key generated in step 2; click "Encrypt file".
   *Expected result:* success message naming AES-256-GCM + RSA-OAEP-SHA256, and a download
   button for the `.enc` container.
   *Say:* "Under the hood, a fresh random AES-256 key and a fresh random nonce were generated
   just for this file, then that small AES key was wrapped with the RSA public key."

5. **(60s) Decrypt Files — happy path.** Go to "My encrypted files", select the file just
   encrypted, enter the correct passphrase, click decrypt.
   *Expected result:* "Decryption successful. Integrity verified." and a download button with
   the exact original file content.

6. **(60–90s) Negative security tests (the important part for faculty).**
   - **Wrong passphrase:** repeat step 5 with an incorrect passphrase.
     *Expected result:* generic "incorrect passphrase" error — no plaintext is ever shown.
   - **Cross-user denial:** log out, register a second account, log in, and try the "Upload a
     .enc container" tab with the first user's downloaded `.enc` file and the correct
     passphrase.
     *Expected result:* "You do not hold the private key required to decrypt this file" — denied
     even with the right passphrase, because the second account doesn't own that RSA key.
   - **Tampered ciphertext:** open the downloaded `.enc` file in a text editor, change one
     character inside `"ciphertext_b64"`, save, and upload it as the first (owning) user with
     the correct passphrase.
     *Expected result:* "the file could not be authenticated" — AES-GCM detected the tampering.

7. **(30s) Security Audit.** Show the audit table: encryption, decryption, denied attempts, and
   integrity failures all logged with timestamps — but no plaintext or passphrases anywhere in
   the "Detail" column. Export the CSV report.

8. **(20s) Overview Dashboard.** Point out that every number shown (files encrypted, successful
   decryptions, blocked attempts, sensitivity distribution) comes from this account's real
   database records, not sample data.

9. **(15s) Close.** "Everything you just saw ran fully offline, no external API calls, and is
   backed by 45 automated tests covering the cryptography, authentication, authorization, and
   AI classification logic — see `docs/TEST_RESULTS.md`."

## Screenshots to capture for a report/slides

- Login/Register screen.
- Key Management: generated key pair with the warning about key loss.
- AI Security Analysis: classification result with probability chart and matched indicators.
- Encrypt Files: success message with algorithm names.
- Decrypt Files: successful decryption message.
- A denied/failed decryption message (wrong passphrase or cross-user).
- Security Audit table showing a mix of SUCCESS/DENIED/FAILURE events.
- Overview Dashboard with the sensitivity-distribution chart.

## If something goes wrong live

- "ML model unavailable" warning → you forgot to run `train_classifier.py`; the app still works
  correctly via the conservative rule-based fallback — this is itself a good talking point about
  fail-safe design.
- Port conflict → `streamlit run app.py --server.port 8502`.
