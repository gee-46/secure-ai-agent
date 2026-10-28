# Project Report: Privacy-Preserving AI Agent for Intelligent Hybrid Encryption and Secure Decryption

## Abstract

This project implements a local-first application that classifies text/document sensitivity
using a locally-trained, explainable machine learning model, deterministically recommends a
security policy, and applies genuine hybrid cryptography (AES-256-GCM + RSA-OAEP-SHA256) to
encrypt and decrypt files. Authentication uses Argon2id password hashing; authorization is
enforced independently of the AI's output, strictly by file ownership. A privacy-conscious
audit log records security-relevant events without ever storing plaintext or secret material.
The system is implemented end-to-end in Python with Streamlit as the UI layer and is validated
by an automated test suite (45 tests, all passing at time of writing).

## Introduction

Modern organizations generate files whose sensitivity varies widely, yet encryption and access
control are often applied uniformly or manually, leading to both over- and under-protection.
This project investigates a middle ground: use a lightweight, explainable, *local* AI model to
suggest a sensitivity tier and a corresponding security policy, while strictly separating that
suggestion from the cryptographic and authorization machinery that actually protects the data.

## Problem definition

Given an arbitrary file or text snippet, (1) estimate how sensitive its contents are, (2) choose
an appropriate, justifiable security policy, and (3) protect the file with real cryptography
such that only an authorized, authenticated party holding the correct key material can recover
it — while never letting the AI's output itself become a security control.

## Objectives and scope

In scope: local text/file sensitivity classification; deterministic policy mapping; AES-256-GCM
+ RSA-OAEP hybrid encryption; passphrase-protected private key storage; Argon2id authentication;
owner-based authorization; tamper detection; privacy-conscious audit logging; a working
Streamlit dashboard covering the full workflow; an automated test suite.

Out of scope (documented limitations, see `docs/THREAT_MODEL.md`): multi-recipient key sharing,
network-layer hardening (TLS/CSRF), cryptographically tamper-proof logging, secure physical
deletion guarantees, and production-grade classification accuracy from a small synthetic
dataset.

## Existing-system limitations

Typical ad hoc approaches either (a) apply a single encryption policy to everything regardless
of sensitivity, wasting effort on low-risk public data and under-protecting high-risk data when
staff forget to apply stricter controls manually, or (b) rely on manual tagging that is
inconsistent and unscalable. Fully automated classification-driven *access control* (letting an
ML model directly grant/deny decryption) is also unsafe, since ML predictions can be wrong or
adversarially manipulated.

## Proposed system

A hybrid approach: ML-assisted sensitivity triage feeds a deterministic policy engine that only
ever recommends *stronger* handling (never bypasses or weakens cryptography/authorization).
Actual access control remains purely deterministic: Argon2id authentication plus
database-verified file ownership. The AI functions as a decision-support and awareness tool,
not a gatekeeper.

## System architecture

See `docs/ARCHITECTURE.md` for the full component diagram, data flow, key lifecycle, and
failure-handling discussion. In summary: `app.py` (Streamlit UI) calls into `src/auth`,
`src/ai`, `src/crypto`, `src/security`, `src/storage`, and `src/audit`, each with a single
clear responsibility and no cross-cutting of cryptography/authorization logic into the UI
layer.

## Functional requirements

- Register/login users; hash passwords with Argon2id; lock accounts after repeated failures.
- Classify pasted text or supported uploaded files (`.txt`, `.md`, `.csv`, `.pdf`) into
  Public / Confidential / Highly Confidential, with probabilities and explainable indicators.
- Allow a justified manual override of the AI classification.
- Recommend and display a deterministic security policy with reasons.
- Generate RSA-3072 key pairs; protect private keys with a user passphrase.
- Encrypt arbitrary files (text or binary) with AES-256-GCM, wrapping the DEK with RSA-OAEP.
- Decrypt only for the authenticated, authorized owner, after passphrase and integrity checks.
- Record audit events for encryption, decryption, denied access, integrity failures,
  classification, policy decisions, and key generation — without secret/plaintext material.
- Provide a dashboard: Overview, AI Analysis, Encrypt, Decrypt, Key Management, Audit, About.

## Non-functional requirements

- **Security**: fail-closed authorization and decryption; no custom cryptographic primitives;
  no hardcoded secrets or default production passwords.
- **Privacy**: no document content or classification data is transmitted externally; audit logs
  exclude plaintext/secrets by construction and by test.
- **Usability**: a clear, consistent dark-themed dashboard with explicit status/explanation for
  every AI and security decision.
- **Testability**: deterministic, automated test coverage for cryptography, authorization, AI
  behavior, and application infrastructure.
- **Portability**: runs on a local Windows/macOS/Linux machine with only `pip`-installable
  dependencies; no paid APIs or cloud services.

## Algorithms used

- **AES-256-GCM** (authenticated symmetric encryption) — NIST SP 800-38D; via
  `cryptography.hazmat.primitives.ciphers.aead.AESGCM`.
- **RSA-OAEP with SHA-256** (asymmetric key wrapping) — RFC 8017; via
  `cryptography.hazmat.primitives.asymmetric.padding.OAEP`.
- **RSA-3072** key generation — `cryptography.hazmat.primitives.asymmetric.rsa`.
- **Argon2id** password hashing — RFC 9106, via `argon2-cffi`'s `PasswordHasher` defaults.
- **PBKDF2-backed PEM encryption** for private-key-at-rest protection — via
  `cryptography`'s `serialization.BestAvailableEncryption`.
- **TF-IDF vectorization + Logistic Regression** — scikit-learn, for sensitivity classification.
- **Deterministic regex pattern matching** — for explainable rule-based sensitivity indicators
  and as a conservative floor that can only escalate, never reduce, the AI's classification.

## Implementation methodology

The system was built bottom-up: (1) the versioned container format and hybrid cryptographic
engine were implemented and unit-tested first, since correctness here is safety-critical; (2)
authentication and authorization were implemented and tested next, since they gate all
decryption; (3) the AI classifier and deterministic policy engine were implemented and
unit-tested, with an explicit conservative fallback when the model is unavailable; (4) the
audit log and safe file-storage layer were added; (5) the Streamlit dashboard was built to wire
all of the above together, with no cryptography/authorization logic duplicated in the UI layer;
(6) the application was run and driven end-to-end (including through Streamlit's `AppTest`
framework and direct backend calls matching the UI's own code paths) to verify the full
register → login → classify → encrypt → decrypt workflow and several negative security tests
(wrong passphrase, cross-user access, tampered ciphertext) all behave correctly.

## Test cases and observed results

See `docs/TEST_RESULTS.md` for the exact commands run and their actual output. Summary: 45
automated tests across cryptography (round-trips for text/binary/empty/large files, tamper
detection for ciphertext/nonce/metadata/wrapped-DEK, malformed/truncated/unsupported-version
containers, wrong key/passphrase), authentication (registration, login, lockout, password
hashing), authorization (ownership enforcement, rate limiting), AI classification (per-class
examples, missing-model fallback, low-confidence flagging, rule-based escalation), and
application infrastructure (schema, audit logging, input validation) — all passing.
Additionally, a live end-to-end run through the real Streamlit app (register, login, generate
key, encrypt, decrypt, plus three negative security scenarios) was executed and passed.

## Results and discussion

The hybrid cryptographic engine correctly recovers exact original bytes for text, binary,
empty, and large files, while reliably rejecting every tested tamper/error scenario. The policy
engine never permits reduced protection regardless of the AI's prediction or any user override.
The classifier, while trained on a deliberately small synthetic dataset, demonstrably
distinguishes the three sensitivity tiers in the held-out split and correctly escalates
classification when deterministic sensitive-pattern indicators are present, even when the ML
model alone would under-classify.

## Limitations

See `docs/THREAT_MODEL.md` for the complete, explicit list. Key points: owner-only decryption
(no multi-recipient sharing in this MVP); small synthetic training dataset (illustrative, not
production-grade accuracy); audit log is not cryptographically tamper-proof; no secure physical
deletion guarantee; no network-layer hardening (this is a localhost academic demonstration).

## Future enhancements

- Multi-recipient sharing via per-recipient DEK wrapping (encrypt the same DEK under multiple
  recipients' RSA public keys, each recorded as its own authorized grant).
- A larger, more diverse, still-synthetic (or properly consented) training dataset, plus
  periodic re-evaluation of classifier accuracy and calibration.
- Hardware-backed key storage (e.g. OS keychain / TPM) instead of passphrase-encrypted PEM files.
- Signed/append-only audit logging for tamper-evidence.
- Optional TLS/reverse-proxy deployment guide for non-localhost use.

## Conclusion

This project demonstrates that an explainable, local AI component can meaningfully assist
security triage without ever being trusted as an access-control mechanism, and that a correctly
implemented hybrid AES-GCM/RSA-OAEP cryptosystem, backed by Argon2id authentication and
server-side authorization checks, can be built, tested, and demonstrated entirely offline for
an academic Data Security and Privacy mini project.

## References

- NIST SP 800-38D, *Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode
  (GCM) and GMAC*.
- RFC 8017, *PKCS #1: RSA Cryptography Specifications Version 2.2* (RSAES-OAEP).
- RFC 9106, *Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications*.
- `cryptography` library documentation: https://cryptography.io/en/latest/
- `argon2-cffi` documentation: https://argon2-cffi.readthedocs.io/
- scikit-learn documentation: https://scikit-learn.org/stable/documentation.html
- Streamlit documentation: https://docs.streamlit.io/
