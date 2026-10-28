"""Streamlit dashboard: Privacy-Preserving AI Agent for Intelligent Hybrid
Encryption and Secure Decryption.

This module is UI-only. All cryptography, authentication, authorization,
classification, and audit logic live in `src/`; this file wires the UI to
those backend functions and never performs cryptographic operations or
authorization checks itself.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import pandas as pd
import plotly.express as px
import streamlit as st

from src.ai.classifier import get_classifier
from src.ai.policy import get_policy, policy_reasons
from src.ai.text_extraction import extract_text_preview
from src.auth.auth_service import AuthError, User, login_user, register_user
from src.audit import audit_log as al
from src.crypto import hybrid, keys
from src.crypto.container import ContainerFormatError, deserialize_container
from src.security.authorization import (
    AuthorizationError,
    RateLimitError,
    check_decrypt_rate_limit,
    record_decrypt_failure,
    record_decrypt_success,
    require_file_owner,
)
from src.storage import file_store, repository
from src.utils.config import SETTINGS
from src.utils.theme import CUSTOM_CSS, badge
from src.utils.validation import ValidationError, sanitize_display_filename, validate_upload_size

st.set_page_config(
    page_title="Privacy-Preserving AI Agent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

PAGES = (
    "Overview Dashboard",
    "AI Security Analysis",
    "Encrypt Files",
    "Decrypt Files",
    "Key Management",
    "Security Audit",
    "About & Documentation",
)


# --------------------------------------------------------------------------- #
# Session / auth helpers
# --------------------------------------------------------------------------- #

def current_user() -> User | None:
    return st.session_state.get("user")


def login_view() -> None:
    st.markdown("## 🛡️ Privacy-Preserving AI Agent")
    st.caption("Intelligent Hybrid Encryption and Secure Decryption — Data Security & Privacy mini project")

    tab_login, tab_register = st.tabs(["Log in", "Register"])

    with tab_login:
        with st.form("login_form"):
            username = st.text_input("Username", key="login_username")
            password = st.text_input("Password", type="password", key="login_password")
            submitted = st.form_submit_button("Log in")
        if submitted:
            try:
                user = login_user(username, password)
                st.session_state.clear()
                st.session_state["user"] = user
                al.record_event(al.EVENT_LOGIN_SUCCESS, al.STATUS_SUCCESS, user.user_id, user.username)
                st.rerun()
            except AuthError as exc:
                al.record_event(al.EVENT_LOGIN_FAILED, al.STATUS_FAILURE, username=username, detail=str(exc))
                st.error(str(exc))

    with tab_register:
        st.info(
            "No demo credentials are hardcoded in this application. Register your own "
            "account, or run `python scripts/create_demo_user.py` locally for a "
            "randomly-generated demo account (printed once to your terminal)."
        )
        with st.form("register_form"):
            new_username = st.text_input("Choose a username", key="register_username")
            new_password = st.text_input("Choose a password", type="password", key="register_password")
            confirm_password = st.text_input("Confirm password", type="password", key="register_confirm")
            submitted_r = st.form_submit_button("Create account")
        if submitted_r:
            if new_password != confirm_password:
                st.error("Passwords do not match.")
            else:
                try:
                    user = register_user(new_username, new_password)
                    al.record_event(al.EVENT_REGISTER, al.STATUS_SUCCESS, user.user_id, user.username)
                    st.success("Account created. Please log in from the 'Log in' tab.")
                except ValidationError as exc:
                    st.error(str(exc))


def sidebar_nav() -> str:
    user = current_user()
    with st.sidebar:
        st.markdown("### 🛡️ Navigation")
        st.caption(f"Signed in as **{user.username}**")
        page = st.radio("Go to", PAGES, label_visibility="collapsed", key="nav_radio")
        st.markdown("<div class='ppaa-divider'></div>", unsafe_allow_html=True)
        if st.button("Log out"):
            st.session_state.clear()
            st.rerun()
    return page


# --------------------------------------------------------------------------- #
# Page: Overview Dashboard
# --------------------------------------------------------------------------- #

def page_overview(user: User) -> None:
    st.markdown("## Overview Dashboard")
    st.caption("All figures below come from this account's actual database records — no simulated data.")

    files = repository.list_files_for_user(user.user_id)
    events = al.query_events(username=user.username, limit=1000)
    decrypt_success = sum(1 for e in events if e.event_type == al.EVENT_DECRYPT_SUCCESS)
    decrypt_denied = sum(
        1 for e in events if e.event_type in (al.EVENT_DECRYPT_DENIED, al.EVENT_INTEGRITY_FAILURE)
    )

    c1, c2, c3, c4 = st.columns(4)
    for col, label, value in (
        (c1, "Encrypted files", len(files)),
        (c2, "Successful decryptions", decrypt_success),
        (c3, "Blocked access attempts", decrypt_denied),
        (c4, "Recorded security events", len(events)),
    ):
        with col:
            st.markdown(
                f"<div class='ppaa-metric'><div style='font-size:0.8rem;color:#94a3b8;'>{label}</div>"
                f"<div style='font-size:1.8rem;font-weight:700;color:#67e8f9;'>{value}</div></div>",
                unsafe_allow_html=True,
            )

    st.markdown("<div class='ppaa-divider'></div>", unsafe_allow_html=True)
    col_a, col_b = st.columns(2)

    with col_a:
        st.markdown("#### Sensitivity distribution")
        dist = repository.classification_distribution(user.user_id)
        if dist:
            df = pd.DataFrame({"Classification": list(dist.keys()), "Count": list(dist.values())})
            fig = px.bar(
                df, x="Classification", y="Count", color="Classification",
                color_discrete_map={
                    "Public": "#22c55e", "Confidential": "#f59e0b", "Highly Confidential": "#ef4444",
                },
            )
            fig.update_layout(
                plot_bgcolor="#0b1120", paper_bgcolor="#0b1120", font_color="#e2e8f0", showlegend=False,
            )
            st.plotly_chart(fig, width="stretch")
        else:
            st.info("No files encrypted yet. Visit 'Encrypt Files' to get started.")

    with col_b:
        st.markdown("#### Recent security events")
        if events:
            rows = [
                {"Time": e.timestamp, "Event": e.event_type, "Status": e.status, "Detail": e.detail or ""}
                for e in events[:10]
            ]
            st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)
        else:
            st.info("No events recorded yet.")


# --------------------------------------------------------------------------- #
# Page: AI Security Analysis
# --------------------------------------------------------------------------- #

def page_ai_analysis(user: User) -> None:
    st.markdown("## AI Security Analysis")
    st.caption(
        "Local TF-IDF + Logistic Regression classifier combined with deterministic pattern "
        "rules. Nothing on this page is sent to any external service."
    )

    source = st.radio("Input type", ["Paste text", "Upload file"], horizontal=True)
    text = ""
    if source == "Paste text":
        text = st.text_area("Enter text to analyze", height=150)
    else:
        uploaded = st.file_uploader("Upload a file for sensitivity analysis", key="ai_upload")
        if uploaded is not None:
            data = uploaded.read()
            result = extract_text_preview(uploaded.name, data)
            if result.supported:
                text = result.text
                st.success(result.note)
            else:
                st.warning(result.note)

    if st.button("Analyze sensitivity", disabled=not text.strip()):
        clf = get_classifier()
        result = clf.classify(text)
        policy = get_policy(result.predicted_label)

        al.record_event(
            al.EVENT_CLASSIFICATION, al.STATUS_SUCCESS, user.user_id, user.username,
            detail=f"label={result.predicted_label};model_available={result.model_available}",
        )

        st.markdown(f"### Predicted classification: {badge(result.predicted_label)}", unsafe_allow_html=True)
        if not result.model_available:
            st.warning("ML model unavailable: this result used the conservative rule-based fallback only.")
        if result.low_confidence:
            st.warning("Low confidence prediction — manual review recommended.")

        prob_df = pd.DataFrame(
            {"Class": list(result.probabilities.keys()), "Probability": list(result.probabilities.values())}
        )
        st.bar_chart(prob_df.set_index("Class"))

        if result.matched_patterns:
            st.markdown("**Matched explainable indicators:**")
            for m in result.matched_patterns:
                st.markdown(f"- `{m.name}` ({m.count} match(es))")
        if result.top_terms:
            st.markdown(f"**Influential terms:** {', '.join(result.top_terms)}")
        for note in result.notes:
            st.caption(f"ℹ️ {note}")

        st.markdown("### Recommended security policy")
        st.markdown(f"**{policy.name}** — {policy.description}")
        for reason in policy_reasons(result.predicted_label, result):
            st.markdown(f"- {reason}")

        st.session_state["last_classification"] = result.predicted_label
        st.session_state["last_confidence"] = result.probabilities[result.predicted_label]

        with st.expander("Override classification manually"):
            override = st.selectbox("Select override classification", ["Public", "Confidential", "Highly Confidential"])
            reason = st.text_input("Justification for override (required)")
            if st.button("Apply override"):
                if not reason.strip():
                    st.error("A justification is required to override the AI classification.")
                else:
                    st.session_state["last_classification"] = override
                    st.session_state["last_confidence"] = 1.0
                    al.record_event(
                        al.EVENT_POLICY_DECISION, al.STATUS_SUCCESS, user.user_id, user.username,
                        detail=f"manual_override={override};reason_len={len(reason)}",
                    )
                    st.success(
                        f"Override applied: {override}. This choice will be used on the Encrypt Files page. "
                        "Note: overriding the AI label never bypasses authentication or authorization."
                    )


# --------------------------------------------------------------------------- #
# Page: Encrypt Files
# --------------------------------------------------------------------------- #

def page_encrypt(user: User) -> None:
    st.markdown("## Encrypt Files")
    st.caption("AES-256-GCM encrypts the file; the data-encryption key is wrapped with RSA-OAEP(SHA-256).")

    my_keys = repository.list_key_pairs_for_user(user.user_id)
    if not my_keys:
        st.warning("You have no RSA key pairs yet. Go to 'Key Management' to generate one first.")
        return

    uploaded = st.file_uploader("Upload a file to encrypt", key="encrypt_upload")
    if uploaded is None:
        return

    data = uploaded.read()
    try:
        validate_upload_size(len(data), SETTINGS.max_upload_mb)
    except ValidationError as exc:
        st.error(str(exc))
        return

    display_name = sanitize_display_filename(uploaded.name)
    st.markdown(f"**File:** `{display_name}` ({len(data):,} bytes)")

    extraction = extract_text_preview(uploaded.name, data)
    clf = get_classifier()
    if extraction.supported:
        result = clf.classify(extraction.text)
    else:
        st.info(extraction.note)
        result = clf.classify("")  # conservative default; user should review/override below

    policy = get_policy(result.predicted_label)
    st.markdown(f"**AI-suggested classification:** {badge(result.predicted_label)}", unsafe_allow_html=True)
    st.markdown(f"**Recommended policy:** {policy.name} — {policy.description}")
    for reason in policy_reasons(result.predicted_label, result):
        st.caption(f"- {reason}")

    final_label = st.selectbox(
        "Confirm or override classification before encrypting",
        ["Public", "Confidential", "Highly Confidential"],
        index=["Public", "Confidential", "Highly Confidential"].index(result.predicted_label),
    )
    override_reason = ""
    if final_label != result.predicted_label:
        override_reason = st.text_input("Reason for overriding the AI suggestion (required)")

    key_labels = {f"{k['label']} ({k['key_id'][:8]})": k for k in my_keys}
    chosen_key_label = st.selectbox("Recipient RSA key (public key used to wrap the DEK)", list(key_labels.keys()))
    chosen_key = key_labels[chosen_key_label]

    if st.button("Encrypt file"):
        if final_label != result.predicted_label and not override_reason.strip():
            st.error("Please provide a reason for the manual override.")
            return

        final_policy = get_policy(final_label)
        public_pem, _ = file_store.load_key_material(Path(chosen_key["public_key_path"]), Path(chosen_key["private_key_path"]))
        public_key = keys.load_public_key(public_pem)

        container_bytes = hybrid.encrypt_file(
            data, public_key, chosen_key["key_id"], final_label, final_policy.name, display_name,
        )
        file_id, path = file_store.save_container(container_bytes)
        repository.create_file_record(
            file_id, user.user_id, display_name, str(path), chosen_key["key_id"],
            final_label, final_policy.name, float(result.probabilities.get(final_label, 1.0)), len(container_bytes),
        )

        al.record_event(al.EVENT_POLICY_DECISION, al.STATUS_SUCCESS, user.user_id, user.username, file_id,
                         detail=f"classification={final_label};policy={final_policy.name};"
                                f"override={'yes' if override_reason else 'no'}")
        al.record_event(al.EVENT_ENCRYPT_SUCCESS, al.STATUS_SUCCESS, user.user_id, user.username, file_id,
                         detail=f"size_bytes={len(container_bytes)}")

        st.success(
            f"File encrypted successfully using AES-256-GCM + RSA-OAEP-SHA256. "
            f"Internal file ID: `{file_id}`."
        )
        st.download_button(
            "Download encrypted container (.enc)",
            data=container_bytes,
            file_name=f"{display_name}.enc",
            mime="application/json",
        )


# --------------------------------------------------------------------------- #
# Page: Decrypt Files
# --------------------------------------------------------------------------- #

def page_decrypt(user: User) -> None:
    st.markdown("## Decrypt Files")
    st.caption(
        "Decryption requires: a valid session, ownership of the file (or its recipient key), "
        "the correct private-key passphrase, and successful AES-GCM authentication."
    )

    tab_mine, tab_upload = st.tabs(["My encrypted files", "Upload a .enc container"])

    with tab_mine:
        my_files = repository.list_files_for_user(user.user_id)
        if not my_files:
            st.info("You have no encrypted files yet.")
        else:
            labels = {f"{f['display_name']} — {f['classification']} — {f['created_at'][:19]}": f for f in my_files}
            chosen_label = st.selectbox("Select a file to decrypt", list(labels.keys()), key="mine_select")
            chosen = labels[chosen_label]
            passphrase = st.text_input("Private key passphrase", type="password", key="mine_pass")
            if st.button("Decrypt selected file"):
                _attempt_decrypt_by_file_id(user, chosen["file_id"], passphrase)

    with tab_upload:
        uploaded = st.file_uploader("Upload an encrypted .enc container", key="decrypt_upload")
        passphrase2 = st.text_input("Private key passphrase", type="password", key="upload_pass")
        if uploaded is not None and st.button("Decrypt uploaded container"):
            _attempt_decrypt_uploaded(user, uploaded.read(), passphrase2)


def _load_authorized_private_key(user: User, recipient_key_id: str, passphrase: str):
    key_record = repository.get_key_pair(recipient_key_id)
    if key_record is None or key_record["owner_user_id"] != user.user_id:
        raise AuthorizationError("You do not hold the private key required to decrypt this file.")
    _, private_pem = file_store.load_key_material(Path(key_record["public_key_path"]), Path(key_record["private_key_path"]))
    return keys.load_private_key(private_pem, passphrase)


def _attempt_decrypt_by_file_id(user: User, file_id: str, passphrase: str) -> None:
    try:
        check_decrypt_rate_limit(user.user_id)
        record = require_file_owner(user.user_id, file_id)
        container_bytes = file_store.load_container(Path(record["container_path"]))
        private_key = _load_authorized_private_key(user, record["recipient_key_id"], passphrase)
        plaintext, header = hybrid.decrypt_file(container_bytes, private_key)
    except RateLimitError as exc:
        st.error(str(exc))
        return
    except AuthorizationError as exc:
        record_decrypt_failure(user.user_id)
        al.record_event(al.EVENT_DECRYPT_DENIED, al.STATUS_DENIED, user.user_id, user.username, file_id, detail=str(exc))
        st.error(str(exc))
        return
    except keys.KeyError_:
        record_decrypt_failure(user.user_id)
        al.record_event(al.EVENT_DECRYPT_DENIED, al.STATUS_FAILURE, user.user_id, user.username, file_id, detail="bad_passphrase")
        st.error("Decryption failed: incorrect passphrase.")
        return
    except hybrid.DecryptionError:
        record_decrypt_failure(user.user_id)
        al.record_event(al.EVENT_INTEGRITY_FAILURE, al.STATUS_FAILURE, user.user_id, user.username, file_id, detail="auth_tag_or_format_failure")
        st.error("Decryption failed: the file could not be authenticated (it may be corrupted or tampered with).")
        return

    record_decrypt_success(user.user_id)
    al.record_event(al.EVENT_DECRYPT_SUCCESS, al.STATUS_SUCCESS, user.user_id, user.username, file_id,
                     detail=f"size_bytes={len(plaintext)}")
    st.success(f"Decryption successful. Integrity verified (AES-GCM). Classification at encryption time: {header.classification}.")
    st.download_button("Download decrypted file", data=plaintext, file_name=header.display_name)


def _attempt_decrypt_uploaded(user: User, container_bytes: bytes, passphrase: str) -> None:
    try:
        check_decrypt_rate_limit(user.user_id)
        header, *_ = deserialize_container(container_bytes)
        private_key = _load_authorized_private_key(user, header.recipient_key_id, passphrase)
        plaintext, header = hybrid.decrypt_file(container_bytes, private_key)
    except RateLimitError as exc:
        st.error(str(exc))
        return
    except ContainerFormatError as exc:
        al.record_event(al.EVENT_INTEGRITY_FAILURE, al.STATUS_FAILURE, user.user_id, user.username, detail="malformed_container")
        st.error(f"Invalid encrypted file: {exc}")
        return
    except AuthorizationError as exc:
        record_decrypt_failure(user.user_id)
        al.record_event(al.EVENT_DECRYPT_DENIED, al.STATUS_DENIED, user.user_id, user.username, detail=str(exc))
        st.error(str(exc))
        return
    except keys.KeyError_:
        record_decrypt_failure(user.user_id)
        al.record_event(al.EVENT_DECRYPT_DENIED, al.STATUS_FAILURE, user.user_id, user.username, detail="bad_passphrase")
        st.error("Decryption failed: incorrect passphrase.")
        return
    except hybrid.DecryptionError:
        record_decrypt_failure(user.user_id)
        al.record_event(al.EVENT_INTEGRITY_FAILURE, al.STATUS_FAILURE, user.user_id, user.username, detail="auth_tag_failure")
        st.error("Decryption failed: the file could not be authenticated (it may be corrupted or tampered with).")
        return

    record_decrypt_success(user.user_id)
    al.record_event(al.EVENT_DECRYPT_SUCCESS, al.STATUS_SUCCESS, user.user_id, user.username,
                     detail=f"size_bytes={len(plaintext)}")
    st.success(f"Decryption successful. Integrity verified (AES-GCM). Classification at encryption time: {header.classification}.")
    st.download_button("Download decrypted file", data=plaintext, file_name=header.display_name)


# --------------------------------------------------------------------------- #
# Page: Key Management
# --------------------------------------------------------------------------- #

def page_keys(user: User) -> None:
    st.markdown("## Key Management")
    st.caption("RSA-3072 key pairs. Private keys are encrypted at rest with your passphrase and never shown on screen.")

    with st.form("keygen_form"):
        label = st.text_input("Key label (e.g. 'My laptop key')", value="my-key", key="keygen_label")
        passphrase = st.text_input("Private key passphrase (min. 8 characters)", type="password", key="keygen_pass")
        confirm = st.text_input("Confirm passphrase", type="password", key="keygen_confirm")
        submitted = st.form_submit_button("Generate RSA-3072 key pair")

    if submitted:
        if passphrase != confirm:
            st.error("Passphrases do not match.")
        elif len(passphrase) < 8:
            st.error("Passphrase must be at least 8 characters.")
        else:
            kp = keys.generate_rsa_keypair(passphrase)
            from src.utils.validation import new_internal_id
            temp_id = new_internal_id()
            public_path, private_path = file_store.save_key_material(temp_id, kp.public_pem, kp.private_pem_encrypted)
            key_id = repository.create_key_pair_record(user.user_id, label, str(public_path), str(private_path))
            al.record_event(al.EVENT_KEY_GENERATED, al.STATUS_SUCCESS, user.user_id, user.username, detail=f"key_id={key_id}")
            st.success(f"Key pair '{label}' generated (RSA-3072, OAEP-SHA256). Key ID: `{key_id}`.")
            st.download_button("Download public key (PEM)", data=kp.public_pem, file_name=f"{label}.public.pem")
            st.download_button(
                "Download encrypted private key backup (PEM)",
                data=kp.private_pem_encrypted, file_name=f"{label}.private.enc.pem",
            )
            st.warning(
                "Back up this private key file and remember your passphrase. If you lose "
                "either one, any file encrypted for this key becomes permanently unrecoverable — "
                "there is no password-reset mechanism for cryptographic keys."
            )

    st.markdown("<div class='ppaa-divider'></div>", unsafe_allow_html=True)
    st.markdown("#### Your key pairs")
    my_keys = repository.list_key_pairs_for_user(user.user_id)
    if my_keys:
        st.dataframe(
            pd.DataFrame([{"Label": k["label"], "Key ID": k["key_id"], "Created": k["created_at"][:19]} for k in my_keys]),
            width="stretch", hide_index=True,
        )
    else:
        st.info("No key pairs yet.")


# --------------------------------------------------------------------------- #
# Page: Security Audit
# --------------------------------------------------------------------------- #

def page_audit(user: User) -> None:
    st.markdown("## Security Audit")
    st.caption(
        "Ordinary application-level logs — not cryptographically tamper-proof. "
        "No plaintext content, passwords, passphrases, private keys, or DEKs are ever logged."
    )

    col1, col2, col3 = st.columns(3)
    with col1:
        event_type = st.selectbox("Event type", ["All"] + sorted({
            al.EVENT_ENCRYPT_SUCCESS, al.EVENT_DECRYPT_SUCCESS, al.EVENT_LOGIN_SUCCESS, al.EVENT_LOGIN_FAILED,
            al.EVENT_DECRYPT_DENIED, al.EVENT_INTEGRITY_FAILURE, al.EVENT_CLASSIFICATION,
            al.EVENT_POLICY_DECISION, al.EVENT_KEY_GENERATED, al.EVENT_REGISTER,
        }))
    with col2:
        start_date = st.date_input("From date", value=None)
    with col3:
        end_date = st.date_input("To date", value=None)

    events = al.query_events(
        username=user.username,
        event_type=None if event_type == "All" else event_type,
        start_date=str(start_date) if start_date else None,
        end_date=f"{end_date}T23:59:59" if end_date else None,
        limit=1000,
    )

    if not events:
        st.info("No matching audit events.")
        return

    df = pd.DataFrame([
        {"Time": e.timestamp, "Event": e.event_type, "Status": e.status, "File ID": e.file_id or "", "Detail": e.detail or ""}
        for e in events
    ])
    st.dataframe(df, width="stretch", hide_index=True)

    denied_or_failed = df[df["Status"].isin(["DENIED", "FAILURE"])]
    st.markdown(f"**Failed / denied events in view:** {len(denied_or_failed)}")

    st.download_button(
        "Export filtered audit report (CSV)",
        data=df.to_csv(index=False).encode("utf-8"),
        file_name="audit_report.csv",
        mime="text/csv",
    )


# --------------------------------------------------------------------------- #
# Page: About & Documentation
# --------------------------------------------------------------------------- #

def page_about() -> None:
    st.markdown("## About & Documentation")
    st.markdown(
        """
This is a local-first academic mini project for **Data Security and Privacy**.
It demonstrates a privacy-preserving AI agent that classifies text sensitivity
and applies hybrid cryptography accordingly.

**Architecture at a glance**
- **AI classification**: local TF-IDF + Logistic Regression model, trained on a small
  synthetic dataset (`src/ai/dataset.py`), combined with deterministic regex pattern
  rules (`src/ai/patterns.py`). The AI never grants or denies access by itself.
- **Policy engine**: deterministic mapping from classification → security policy
  (`src/ai/policy.py`). Policies only ever add requirements; they never weaken
  cryptography or bypass authorization.
- **Hybrid encryption**: AES-256-GCM encrypts file content with a fresh 256-bit DEK
  and a fresh 96-bit nonce per file; the DEK is wrapped with the recipient's RSA-3072
  public key using RSA-OAEP(SHA-256) (`src/crypto/hybrid.py`).
- **Key protection**: private keys are stored PEM-encoded and encrypted at rest with a
  passphrase-derived key (`cryptography`'s `BestAvailableEncryption`, PBKDF2-backed).
- **Authentication**: Argon2id password hashing (`argon2-cffi`), with per-account
  lockout after repeated failed attempts.
- **Authorization**: decryption is restricted to the file's owner (or the registered
  owner of the matching RSA key, for re-uploaded containers) — never based on filenames,
  claimed user IDs, or the classification embedded in the container.
- **Audit log**: structured SQLite table, parameterized queries only, and no
  secret/plaintext material is ever written to it.

See `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`, `docs/PROJECT_REPORT.md`, and
`docs/VIVA_QUESTIONS.md` in the repository for full details.

**Limitations (also see docs/THREAT_MODEL.md)**
- This is an academic MVP: only the file owner can decrypt (no multi-recipient sharing).
- The training dataset is small and synthetic; classification accuracy is illustrative,
  not production-grade.
- Deleting a file from this app does not guarantee secure physical erasure on disk/SSD
  or in any backups.
- The audit log is an ordinary database table, not a cryptographically tamper-evident
  ledger.
"""
    )


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def main() -> None:
    user = current_user()
    if user is None:
        login_view()
        return

    page = sidebar_nav()
    if page == "Overview Dashboard":
        page_overview(user)
    elif page == "AI Security Analysis":
        page_ai_analysis(user)
    elif page == "Encrypt Files":
        page_encrypt(user)
    elif page == "Decrypt Files":
        page_decrypt(user)
    elif page == "Key Management":
        page_keys(user)
    elif page == "Security Audit":
        page_audit(user)
    elif page == "About & Documentation":
        page_about()


if __name__ == "__main__":
    main()
