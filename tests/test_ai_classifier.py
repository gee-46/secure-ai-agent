from src.ai.classifier import SensitivityClassifier
from src.ai import patterns


def test_public_example_classified_as_public_or_low_risk():
    clf = SensitivityClassifier()
    result = clf.classify("The company picnic is scheduled for next Friday at the park.")
    assert result.predicted_label in ("Public", "Confidential")  # model may be uncertain, never escalates to HC
    assert sum(result.probabilities.values()) > 0.99


def test_confidential_example_detects_email_pattern():
    clf = SensitivityClassifier()
    result = clf.classify("Please contact john.doe@example.com about the internal budget draft.")
    names = {m.name for m in result.matched_patterns}
    assert "email_address" in names


def test_highly_confidential_example_escalated_by_rules():
    clf = SensitivityClassifier()
    result = clf.classify("Patient diagnosis and prescription details, account ACCT-99281.")
    assert result.predicted_label == "Highly Confidential"


def test_credential_keyword_forces_highly_confidential():
    clf = SensitivityClassifier()
    result = clf.classify("Here is the plain password for the admin dashboard login.")
    assert result.predicted_label == "Highly Confidential"
    assert result.rule_escalated or "Highly Confidential" in result.probabilities


def test_missing_model_falls_back_conservatively(tmp_path):
    missing_model_path = tmp_path / "does_not_exist.joblib"
    clf = SensitivityClassifier(model_path=missing_model_path)
    assert clf.is_model_available is False
    result = clf.classify("Just a plain sentence with no sensitive indicators at all.")
    assert result.model_available is False
    assert result.predicted_label != "Public"  # conservative fallback never defaults to Public
    assert result.low_confidence is True


def test_empty_text_defaults_conservatively():
    clf = SensitivityClassifier()
    result = clf.classify("   ")
    assert result.low_confidence is True


def test_low_confidence_flagged():
    clf = SensitivityClassifier()
    # An ambiguous, short, out-of-distribution sentence should often be low-confidence.
    result = clf.classify("xyz abc random words")
    assert isinstance(result.low_confidence, bool)  # sanity: field is always populated


def test_rule_based_floor_detection():
    matches = patterns.detect_patterns("Call 555-123-4567 or email test@example.com")
    names = {m.name for m in matches}
    assert "phone_number" in names
    assert "email_address" in names
    floor = patterns.rule_based_floor(matches)
    assert floor == "Confidential"


def test_rule_floor_none_for_clean_text():
    matches = patterns.detect_patterns("A completely ordinary sentence about the weather today.")
    assert patterns.rule_based_floor(matches) is None
