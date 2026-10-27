"""Deterministic pattern detectors used alongside the ML classifier.

These are intentionally simple, explainable regex rules over synthetic-style
identifiers. They are a defense-in-depth signal, not a substitute for the
ML model: a rule match can only escalate the required sensitivity floor,
never weaken it or bypass authorization.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

_PATTERNS: dict[str, re.Pattern] = {
    "email_address": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "phone_number": re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "account_like_identifier": re.compile(r"\b(?:ACC|ACCT|CARD|SSN|ID)[-:\s]?\d{4,}\b", re.IGNORECASE),
    "credit_card_like": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
    "financial_keyword": re.compile(
        r"\b(salary|invoice|bank account|routing number|credit score|tax id|wire transfer)\b",
        re.IGNORECASE,
    ),
    "medical_keyword": re.compile(
        r"\b(diagnosis|patient|prescription|medical record|hiv|treatment plan|health insurance)\b",
        re.IGNORECASE,
    ),
    "credential_keyword": re.compile(
        r"\b(password|passphrase|api key|secret key|private key)\b", re.IGNORECASE
    ),
}


@dataclass(frozen=True)
class PatternMatch:
    name: str
    count: int


def detect_patterns(text: str) -> list[PatternMatch]:
    matches: list[PatternMatch] = []
    for name, pattern in _PATTERNS.items():
        found = pattern.findall(text)
        if found:
            matches.append(PatternMatch(name=name, count=len(found)))
    return matches


def rule_based_floor(matches: list[PatternMatch]) -> str | None:
    """Return a minimum-required classification implied by matched patterns, or None."""
    names = {m.name for m in matches}
    highly_confidential_triggers = {
        "account_like_identifier", "credit_card_like", "medical_keyword", "credential_keyword",
    }
    confidential_triggers = {"email_address", "phone_number", "financial_keyword"}

    if names & highly_confidential_triggers:
        return "Highly Confidential"
    if names & confidential_triggers:
        return "Confidential"
    return None
