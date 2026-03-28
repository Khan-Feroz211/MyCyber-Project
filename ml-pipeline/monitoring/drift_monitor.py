"""Evidently AI drift monitor for PII classification inputs."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
from evidently import ColumnMapping
from evidently.metric_preset import DataDriftPreset
from evidently.report import Report
from prometheus_client import Gauge

DLP_DRIFT_SCORE = Gauge(
    "dlp_drift_score",
    "Evidently data drift score for PII classifier features",
)

REPORTS_DIR = Path(os.getenv("DRIFT_REPORTS_DIR", "experiments/drift_reports"))
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
DRIFT_THRESHOLD = float(os.getenv("DRIFT_THRESHOLD", "0.2"))


def compute_drift(
    reference_df: pd.DataFrame,
    current_df: pd.DataFrame,
    column_mapping: ColumnMapping | None = None,
) -> float:
    """Run Evidently drift report, persist JSON, update Prometheus gauge.

    Returns the share of drifted features (0.0 – 1.0).
    """
    report = Report(metrics=[DataDriftPreset()])
    report.run(
        reference_data=reference_df,
        current_data=current_df,
        column_mapping=column_mapping,
    )

    result = report.as_dict()
    drift_share: float = result["metrics"][0]["result"]["share_of_drifted_columns"]

    DLP_DRIFT_SCORE.set(drift_share)

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    report_path = REPORTS_DIR / f"drift_{ts}.json"
    report_path.write_text(json.dumps(result, indent=2))

    return drift_share


def check_and_alert(reference_df: pd.DataFrame, current_df: pd.DataFrame) -> bool:
    """Returns True if drift exceeds threshold (retrain should be triggered)."""
    drift = compute_drift(reference_df, current_df)
    print(f"Drift score: {drift:.4f} (threshold: {DRIFT_THRESHOLD})")
    return drift > DRIFT_THRESHOLD
