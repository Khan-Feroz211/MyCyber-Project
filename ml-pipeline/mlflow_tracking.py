"""MLflow experiment tracking helpers."""
from __future__ import annotations

from contextlib import contextmanager
from typing import Any

import mlflow


@contextmanager
def dlp_run(run_name: str, experiment_name: str = "dlp-pii-classifier"):
    """Context manager for a tracked MLflow run."""
    mlflow.set_experiment(experiment_name)
    with mlflow.start_run(run_name=run_name) as run:
        yield run


def log_training_run(
    params: dict[str, Any],
    metrics: dict[str, float],
    artifacts: list[str],
    model_obj: Any,
    experiment_name: str = "dlp-pii-classifier",
) -> str:
    """Log a full training run and return the run_id."""
    with dlp_run("train", experiment_name) as run:
        mlflow.log_params(params)
        mlflow.log_metrics(metrics)
        for artifact in artifacts:
            mlflow.log_artifact(artifact)
        mlflow.sklearn.log_model(model_obj, artifact_path="model")
        return run.info.run_id
