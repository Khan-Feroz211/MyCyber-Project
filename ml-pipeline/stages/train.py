"""Stage 2: Train RandomForest classifier and log to MLflow."""
from __future__ import annotations

from pathlib import Path

import joblib
import mlflow
import mlflow.sklearn
import numpy as np
import yaml
from sklearn.ensemble import RandomForestClassifier

PARAMS_ALL = yaml.safe_load(open("params.yaml"))
PARAMS = PARAMS_ALL["train"]
REG_PARAMS = PARAMS_ALL["register"]
PROC_DIR = Path("data/processed")
MODEL_DIR = Path("models")
MODEL_DIR.mkdir(parents=True, exist_ok=True)

mlflow.set_tracking_uri(REG_PARAMS["mlflow_tracking_uri"])
mlflow.set_experiment(REG_PARAMS["experiment_name"])


def main() -> None:
    X_train = np.load(PROC_DIR / "X_train.npy")
    y_train = np.load(PROC_DIR / "y_train.npy")

    with mlflow.start_run(run_name="train") as run:
        clf = RandomForestClassifier(
            n_estimators=PARAMS["n_estimators"],
            max_depth=PARAMS["max_depth"],
            random_state=PARAMS["random_state"],
            n_jobs=-1,
        )
        clf.fit(X_train, y_train)

        mlflow.log_params(PARAMS)
        mlflow.sklearn.log_model(clf, artifact_path="model")

        model_path = MODEL_DIR / "dlp_classifier.joblib"
        joblib.dump(clf, model_path)
        mlflow.log_artifact(str(model_path))

        print(f"Model trained. Run ID: {run.info.run_id}")


if __name__ == "__main__":
    main()
