"""Stage 1: Preprocess raw text data into feature arrays."""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import yaml
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
import joblib

PARAMS = yaml.safe_load(open("params.yaml"))["preprocess"]
RAW_DIR = Path("data/raw")
PROC_DIR = Path("data/processed")
PROC_DIR.mkdir(parents=True, exist_ok=True)


def load_samples() -> tuple[list[str], list[int]]:
    """Load labelled text samples from JSONL files in data/raw/."""
    texts, labels = [], []
    for fpath in RAW_DIR.glob("*.jsonl"):
        with open(fpath) as f:
            for line in f:
                record = json.loads(line.strip())
                texts.append(record["text"])
                labels.append(int(record["label"]))
    if not texts:
        raise RuntimeError(f"No .jsonl files found in {RAW_DIR}")
    return texts, labels


def main() -> None:
    texts, labels = load_samples()
    vectorizer = TfidfVectorizer(max_features=10_000, ngram_range=(1, 2))
    X = vectorizer.fit_transform(texts)
    y = np.array(labels)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=PARAMS["test_size"],
        random_state=PARAMS["random_state"],
        stratify=y,
    )

    np.save(PROC_DIR / "X_train.npy", X_train.toarray())
    np.save(PROC_DIR / "X_test.npy", X_test.toarray())
    np.save(PROC_DIR / "y_train.npy", y_train)
    np.save(PROC_DIR / "y_test.npy", y_test)
    joblib.dump(vectorizer, PROC_DIR / "vectorizer.joblib")
    print(
        f"Preprocessed {len(texts)} samples. Train={len(y_train)}, Test={len(y_test)}"
    )


if __name__ == "__main__":
    main()
