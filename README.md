# Privacy-Preserving AI Agent for Intelligent Hybrid Encryption and Secure Decryption

A local-first academic mini project for **Data Security and Privacy**. It combines a
locally-trained, explainable AI sensitivity classifier with a deterministic security-policy
engine and real, tested hybrid cryptography (AES-256-GCM + RSA-OAEP) to encrypt and decrypt
files, enforce authentication/authorization, and maintain privacy-conscious audit logs — all
through a Streamlit dashboard.

No external APIs, cloud services, or LLMs are used. Everything runs locally.

## Problem statement

Organizations handle files of widely varying sensitivity (public announcements vs. medical or
financial records) but often apply uniform, manual security practices. This project explores
whether a *local, explainable* ML component can help triage sensitivity and recommend an
appropriate security policy, while keeping cryptography, authentication, and authorization
fully deterministic and never dependent on the AI's output for access decisions.

## Objectives

1. Classify uploaded text/files into Public / Confidential / Highly Confidential using a real,
   local, explainable ML pipeline.
2. Deterministically map classifications to security policies.
3. Encrypt files with a genuine hybrid cryptosystem: AES-256-GCM + RSA-OAEP(SHA-256).
4. Protect private keys at rest with passphrase-derived encryption.
5. Authenticate users (Argon2id) and authorize decryption strictly by file ownership.
6. Detect tampering via AES-GCM authentication (fail closed, no partial plaintext ever).
7. Maintain a privacy-conscious, queryable audit log.
8. Present all of the above through a usable, professional dashboard.

## Features

- Argon2id password hashing, account lockout after repeated failed logins.
- TF-IDF + Logistic Regression sensitivity classifier, combined with explainable regex rules
  (emails, phone numbers, account-like IDs, financial/medical/credential keywords).
- Deterministic policy engine (`src/ai/policy.py`) — AI never grants/denies access.
- AES-256-GCM encryption with a fresh 256-bit DEK and 96-bit nonce per file; RSA-3072-OAEP-SHA256
  key wrapping; authenticated header metadata (AAD).
- Versioned, validated JSON container format with Base64-encoded binary fields.
- Owner-only decryption authorization, decrypt rate-limiting/lockout.
- Privacy-conscious audit log (SQLite, parameterized queries, no secrets/plaintext logged).
- Streamlit dashboard: Overview, AI Security Analysis, Encrypt, Decrypt, Key Management,
  Security Audit, About.

## Technology stack

Python 3.11+ (tested on 3.13) · Streamlit · `cryptography` · scikit-learn · SQLite ·
argon2-cffi (Argon2id) · pytest · Plotly · pandas · pypdf · python-dotenv.

## Installation

```bash
cd privacy-preserving-ai-agent
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
copy .env.example .env      # Windows; or: cp .env.example .env
```

## Configuration

Edit `.env` if you want non-default paths/limits (see `.env.example`). No secrets or API keys
are required — the application never calls any external service.

## First-time setup

```bash
python scripts/initialize_db.py      # creates the SQLite schema
python scripts/train_classifier.py   # trains and saves the local ML model
```

Then either register your own account from the app's "Register" tab, or create a random,
locally-generated demo account (password is printed once, never hardcoded):

```bash
python scripts/create_demo_user.py
```

## Running the application

```bash
streamlit run app.py
```

Open the printed local URL (default `http://localhost:8501`) in a browser.

## Encryption and decryption workflow

1. **Analyze** — paste text or upload a supported file (`.txt`, `.md`, `.csv`, `.pdf`) on
   "AI Security Analysis" or directly on "Encrypt Files". The classifier returns a label,
   class probabilities, and matched explainable indicators.
2. **Policy** — the deterministic policy engine recommends a security policy; you may override
   the classification with a documented justification (overrides never bypass authentication).
3. **Encrypt** — pick (or generate, under "Key Management") an RSA-3072 recipient key. The app
   generates a fresh AES-256 DEK and 96-bit nonce, encrypts the file with AES-GCM, wraps the DEK
   with RSA-OAEP-SHA256, and serializes everything into a versioned JSON container. Download it.
4. **Decrypt** — from "Decrypt Files", either pick one of your own stored files or upload a
   `.enc` container. Enter the private key's passphrase. The app verifies ownership, unwraps the
   DEK, and only releases plaintext after the AES-GCM authentication tag verifies.
5. **Audit** — every step above is recorded in "Security Audit" without any secret or plaintext
   material.

## Testing

```bash
python -m pytest tests/ -v
```

As of this writing: **52 passed**, 0 failed (see `docs/TEST_RESULTS.md` for the full recorded
run). Tests cover cryptographic round-trips and tamper detection, authentication/authorization,
AI classification behavior (including fallback and low-confidence paths), and application
infrastructure (DB schema, audit logging, input validation).

## Troubleshooting

- **"ML model unavailable" banner** — run `python scripts/train_classifier.py` to (re)generate
  `models/sensitivity_classifier.joblib`.
- **`sqlite3.OperationalError: no such table`** — run `python scripts/initialize_db.py`.
- **Decryption always fails** — confirm you're using the exact passphrase for the RSA key that
  was used as the *recipient* at encryption time; a wrong passphrase or wrong key both fail
  closed with a generic error by design.
- **Streamlit port already in use** — run `streamlit run app.py --server.port 8502`.

## Limitations

- **Owner-only decryption (MVP scope)** — no multi-recipient sharing workflow is implemented;
  see `docs/ARCHITECTURE.md` and `docs/THREAT_MODEL.md`.
- **Small, synthetic training dataset** — the classifier is a genuine, working ML pipeline, but
  its ~36-example dataset is illustrative, not production-grade accuracy.
- **No tamper-proof audit log** — it is an ordinary SQLite table; see `docs/THREAT_MODEL.md`.
- **No secure physical erasure guarantee** — deleting a file/record does not guarantee removal
  from disk/SSD wear-leveled storage or backups.
- **Local, single-machine threat model** — this is an academic demonstration, not a
  production-hardened system (see `docs/THREAT_MODEL.md` for full discussion).

## Documentation

- [`docs/PROJECT_REPORT.md`](docs/PROJECT_REPORT.md) — full academic report.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — components, data flow, key lifecycle.
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — assets, attackers, mitigations, residual risk.
- [`docs/VIVA_QUESTIONS.md`](docs/VIVA_QUESTIONS.md) — 25+ likely viva Q&A.
- [`docs/DEMO_SCRIPT.md`](docs/DEMO_SCRIPT.md) — 5–8 minute live demo script.
- [`docs/TEST_RESULTS.md`](docs/TEST_RESULTS.md) — actual executed test results.
