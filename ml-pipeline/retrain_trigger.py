"""Automated retraining trigger — fires DVC repro when drift exceeds threshold."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pandas as pd

from monitoring.drift_monitor import check_and_alert

REFERENCE_DATA_PATH = Path(
    os.getenv("REFERENCE_DATA_PATH", "data/processed/reference.parquet")
)
CURRENT_DATA_PATH = Path(
    os.getenv("CURRENT_DATA_PATH", "data/processed/current.parquet")
)


def load_data() -> tuple[pd.DataFrame, pd.DataFrame]:
    if not REFERENCE_DATA_PATH.exists():
        raise FileNotFoundError(f"Reference data not found: {REFERENCE_DATA_PATH}")
    if not CURRENT_DATA_PATH.exists():
        raise FileNotFoundError(f"Current data not found: {CURRENT_DATA_PATH}")
    return pd.read_parquet(REFERENCE_DATA_PATH), pd.read_parquet(CURRENT_DATA_PATH)


def trigger_retrain() -> None:
    print("Drift threshold exceeded — triggering DVC pipeline rerun...")
    result = subprocess.run(
        ["dvc", "repro", "--force"],
        capture_output=False,
        check=False,
    )
    if result.returncode != 0:
        print("Retraining pipeline failed. Check DVC output above.", file=sys.stderr)
        sys.exit(result.returncode)
    print("Retraining pipeline completed successfully.")


def main() -> None:
    reference_df, current_df = load_data()
    should_retrain = check_and_alert(reference_df, current_df)
    if should_retrain:
        trigger_retrain()
    else:
        print("Drift within acceptable range. No retraining needed.")


if __name__ == "__main__":
    main()
