"""Train and persist the TF-IDF + Logistic Regression sensitivity classifier.

Usage: python scripts/train_classifier.py

This is fully reproducible: the dataset is a fixed list in
src/ai/dataset.py and a fixed random_state is used for the model.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report

from src.ai.dataset import TRAINING_EXAMPLES
from src.utils.config import SETTINGS

RANDOM_STATE = 42


def main() -> None:
    texts = [t for t, _ in TRAINING_EXAMPLES]
    labels = [lbl for _, lbl in TRAINING_EXAMPLES]

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(lowercase=True, ngram_range=(1, 2), min_df=1)),
        ("clf", LogisticRegression(max_iter=1000, random_state=RANDOM_STATE)),
    ])

    x_train, x_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.25, random_state=RANDOM_STATE, stratify=labels
    )

    pipeline.fit(x_train, y_train)

    print("=== Held-out evaluation (small synthetic dataset; not production accuracy) ===")
    predictions = pipeline.predict(x_test)
    print(classification_report(y_test, predictions, zero_division=0))

    # Refit on the full dataset for the persisted model used by the app.
    pipeline.fit(texts, labels)

    SETTINGS.model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, SETTINGS.model_path)
    print(f"Model saved to: {SETTINGS.model_path}")


if __name__ == "__main__":
    main()
