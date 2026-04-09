"""
DVC Stage 1: preprocess

Reads ml/data/raw/pii_samples.csv, validates columns, splits into
train (80%) and test (20%) sets, and saves to ml/data/processed/.
Split ratio is loaded from params.yaml (evaluation.test_split).
"""

import sys
from pathlib import Path

import pandas as pd
import yaml


def _load_params() -> dict:
    params_path = Path("params.yaml")
    if not params_path.exists():
        return {"evaluation": {"test_split": 0.2}}
    with open(params_path) as f:
        return yaml.safe_load(f)


def preprocess() -> None:
    raw_path = Path("ml/data/raw/pii_samples.csv")
    processed_path = Path("ml/data/processed")
    processed_path.mkdir(parents=True, exist_ok=True)

    if not raw_path.exists():
        print(f"ERROR: Input file not found: {raw_path}")
        sys.exit(1)

    params = _load_params()
    test_split: float = params.get("evaluation", {}).get("test_split", 0.2)
    train_fraction = 1.0 - test_split

    df = pd.read_csv(raw_path)
    required_cols = ["id", "text", "expected_entities", "expected_severity"]
    missing = [c for c in required_cols if c not in df.columns]
    if missing:
        print(f"ERROR: Missing columns: {missing}")
        sys.exit(1)

    df = df.dropna(subset=["text"])
    split_idx = int(len(df) * train_fraction)
    train_df = df.iloc[:split_idx]
    test_df = df.iloc[split_idx:]

    train_df.to_csv(processed_path / "train.csv", index=False)
    test_df.to_csv(processed_path / "test.csv", index=False)

    print(f"Total samples: {len(df)}")
    print(f"Train: {len(train_df)}, Test: {len(test_df)}")
    print(f"Split: {train_fraction:.0%} / {test_split:.0%}")


if __name__ == "__main__":
    preprocess()
