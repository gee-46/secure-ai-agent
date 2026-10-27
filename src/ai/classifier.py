"""Local, explainable sensitivity classifier: TF-IDF + Logistic Regression,
combined deterministically with regex pattern rules.

The AI prediction alone never grants or denies access; it only feeds the
policy engine's *recommendation* (see src/ai/policy.py). Authorization is
always enforced independently (see src/security/authorization.py).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import joblib

from src.ai.patterns import PatternMatch, detect_patterns, rule_based_floor
from src.utils.config import SETTINGS

LABELS = ("Public", "Confidential", "Highly Confidential")
_LABEL_RANK = {label: i for i, label in enumerate(LABELS)}

LOW_CONFIDENCE_THRESHOLD = 0.5


@dataclass(frozen=True)
class ClassificationResult:
    predicted_label: str
    probabilities: dict[str, float]
    matched_patterns: list[PatternMatch] = field(default_factory=list)
    model_available: bool = True
    low_confidence: bool = False
    rule_escalated: bool = False
    top_terms: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


class SensitivityClassifier:
    """Wraps a trained scikit-learn pipeline; falls back to rules if unavailable."""

    def __init__(self, model_path: Path | None = None):
        self._model_path = model_path or SETTINGS.model_path
        self._pipeline = None
        if self._model_path.exists():
            try:
                self._pipeline = joblib.load(self._model_path)
            except Exception:
                self._pipeline = None

    @property
    def is_model_available(self) -> bool:
        return self._pipeline is not None

    def _top_influential_terms(self, text: str, predicted_label: str, top_n: int = 5) -> list[str]:
        """Return terms in the input most associated with the predicted class."""
        try:
            vectorizer = self._pipeline.named_steps["tfidf"]
            clf = self._pipeline.named_steps["clf"]
            class_index = list(clf.classes_).index(predicted_label)
            coefs = clf.coef_[class_index]
            vocab = vectorizer.vocabulary_
            x = vectorizer.transform([text])
            indices = x.nonzero()[1]
            scored = sorted(
                ((coefs[i], term) for term, i in vocab.items() if i in indices),
                reverse=True,
            )
            return [term for _, term in scored[:top_n]]
        except Exception:
            return []

    def classify(self, text: str) -> ClassificationResult:
        matches = detect_patterns(text)
        floor = rule_based_floor(matches)
        notes: list[str] = []

        if not text or not text.strip():
            return ClassificationResult(
                predicted_label="Public",
                probabilities={label: (1.0 if label == "Public" else 0.0) for label in LABELS},
                matched_patterns=matches,
                model_available=self.is_model_available,
                low_confidence=True,
                notes=["Empty or unsupported content: defaulted to the most conservative "
                       "non-trivial label review is still recommended."],
            )

        if self._pipeline is None:
            # Conservative fallback: no ML model -> rely on rules only, flag uncertainty.
            label = floor or "Confidential"  # never default to Public without a model
            notes.append("ML model unavailable; classification is rule-based only (conservative fallback).")
            return ClassificationResult(
                predicted_label=label,
                probabilities={lbl: (1.0 if lbl == label else 0.0) for lbl in LABELS},
                matched_patterns=matches,
                model_available=False,
                low_confidence=True,
                rule_escalated=floor is not None,
                notes=notes,
            )

        proba = self._pipeline.predict_proba([text])[0]
        classes = list(self._pipeline.named_steps["clf"].classes_)
        probabilities = {cls: float(p) for cls, p in zip(classes, proba)}
        ml_label = max(probabilities, key=probabilities.get)
        top_confidence = probabilities[ml_label]
        low_confidence = top_confidence < LOW_CONFIDENCE_THRESHOLD

        final_label = ml_label
        rule_escalated = False
        if floor and _LABEL_RANK[floor] > _LABEL_RANK[ml_label]:
            final_label = floor
            rule_escalated = True
            notes.append(
                f"Escalated from '{ml_label}' to '{floor}' because sensitive patterns were detected."
            )

        if low_confidence:
            notes.append("Model confidence is low; manual review of this classification is recommended.")

        top_terms = self._top_influential_terms(text, ml_label)

        return ClassificationResult(
            predicted_label=final_label,
            probabilities=probabilities,
            matched_patterns=matches,
            model_available=True,
            low_confidence=low_confidence,
            rule_escalated=rule_escalated,
            top_terms=top_terms,
            notes=notes,
        )


_classifier_singleton: SensitivityClassifier | None = None


def get_classifier() -> SensitivityClassifier:
    global _classifier_singleton
    if _classifier_singleton is None:
        _classifier_singleton = SensitivityClassifier()
    return _classifier_singleton
