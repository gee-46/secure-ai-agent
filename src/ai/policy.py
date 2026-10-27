"""Deterministic security-policy engine.

Maps a sensitivity classification to a security policy. This mapping is
fixed application logic, not an ML decision: the AI component only
*recommends* a classification; this engine deterministically decides the
resulting policy, and policies never weaken cryptography or bypass
authorization regardless of classification.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SecurityPolicy:
    name: str
    classification: str
    requires_authenticated_encryption: bool
    requires_protected_key_storage: bool
    requires_strict_access_verification: bool
    enhanced_audit: bool
    description: str


_POLICIES: dict[str, SecurityPolicy] = {
    "Public": SecurityPolicy(
        name="Standard",
        classification="Public",
        requires_authenticated_encryption=True,
        requires_protected_key_storage=False,
        requires_strict_access_verification=False,
        enhanced_audit=False,
        description="Standard authenticated encryption (AES-256-GCM with RSA-OAEP key wrap).",
    ),
    "Confidential": SecurityPolicy(
        name="Confidential",
        classification="Confidential",
        requires_authenticated_encryption=True,
        requires_protected_key_storage=True,
        requires_strict_access_verification=True,
        enhanced_audit=False,
        description=(
            "Authenticated encryption, passphrase-protected private key storage, "
            "and authenticated user access required for decryption."
        ),
    ),
    "Highly Confidential": SecurityPolicy(
        name="Strict",
        classification="Highly Confidential",
        requires_authenticated_encryption=True,
        requires_protected_key_storage=True,
        requires_strict_access_verification=True,
        enhanced_audit=True,
        description=(
            "Authenticated encryption, passphrase-protected private key storage, "
            "stricter access verification, and enhanced audit logging."
        ),
    ),
}


def get_policy(classification: str) -> SecurityPolicy:
    """Every classification maps to AT LEAST authenticated encryption and
    authorization; unrecognized labels fail closed to the strictest policy."""
    return _POLICIES.get(classification, _POLICIES["Highly Confidential"])


def policy_reasons(classification: str, result) -> list[str]:
    """Human-readable reasons for the chosen policy, for UI display."""
    reasons = [f"Predicted sensitivity: {classification}."]
    if result.rule_escalated:
        reasons.append("Pattern-based rules escalated the required policy for safety.")
    if result.low_confidence:
        reasons.append("Classification confidence was low; review is recommended.")
    if result.matched_patterns:
        names = ", ".join(sorted({m.name for m in result.matched_patterns}))
        reasons.append(f"Detected indicators: {names}.")
    if not result.model_available:
        reasons.append("ML model unavailable; conservative rule-based fallback was used.")
    reasons.append(
        "All policies require AES-256-GCM authenticated encryption and authenticated, "
        "authorized decryption regardless of classification."
    )
    return reasons
