"""Stage 3: Evaluate model and enforce F1 gate."""

from __future__ import annotations

import json
from pathlib import Path

import joblib
import mlflow
import numpy as np
import yaml
from sklearn.metrics import classification_report, f1_score

PARAMS_ALL = yaml.safe_load(open("params.yaml"))
PARAMS = PARAMS_ALL["evaluate"]
REG_PARAMS = PARAMS_ALL["register"]
PROC_DIR = Path("data/processed")
EXP_DIR = Path("experiments")
EXP_DIR.mkdir(parents=True, exist_ok=True)

mlflow.set_tracking_uri(REG_PARAMS["mlflow_tracking_uri"])
mlflow.set_experiment(REG_PARAMS["experiment_name"])


def main() -> None:
    X_test = np.load(PROC_DIR / "X_test.npy")
    y_test = np.load(PROC_DIR / "y_test.npy")
    clf = joblib.load("models/dlp_classifier.joblib")

    y_pred = clf.predict(X_test)
    f1 = float(f1_score(y_test, y_pred, average="weighted"))
    report = classification_report(y_test, y_pred, output_dict=True)

    metrics = {"f1_weighted": f1, "classification_report": report}
    metrics_path = EXP_DIR / "metrics.json"
    metrics_path.write_text(json.dumps(metrics, indent=2))

    with mlflow.start_run(run_name="evaluate"):
        mlflow.log_metric("f1_weighted", f1)
        mlflow.log_artifact(str(metrics_path))

    threshold = PARAMS["f1_threshold"]
    if f1 < threshold:
        raise SystemExit(
            f"F1={f1:.4f} below gate threshold {threshold}. Promotion blocked."
        )
    print(f"Evaluation passed: F1={f1:.4f} >= {threshold}")


if __name__ == "__main__":
    main()
