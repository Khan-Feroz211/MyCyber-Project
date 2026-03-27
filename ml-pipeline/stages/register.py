"""Stage 4: Register model to MLflow Model Registry."""

from __future__ import annotations

import json
from pathlib import Path

import mlflow
import mlflow.sklearn
import yaml

PARAMS_ALL = yaml.safe_load(open("params.yaml"))
REG_PARAMS = PARAMS_ALL["register"]

mlflow.set_tracking_uri(REG_PARAMS["mlflow_tracking_uri"])
client = mlflow.tracking.MlflowClient()


def get_production_f1(model_name: str) -> float:
    """Return F1 of the current production model, or 0 if none exists."""
    try:
        prod = client.get_model_version_by_alias(
            model_name, REG_PARAMS["production_alias"]
        )
        run = client.get_run(prod.run_id)
        return float(run.data.metrics.get("f1_weighted", 0.0))
    except Exception:
        return 0.0


def main() -> None:
    metrics = json.loads(Path("experiments/metrics.json").read_text())
    new_f1 = float(metrics["f1_weighted"])
    model_name = REG_PARAMS["model_name"]

    prod_f1 = get_production_f1(model_name)
    if new_f1 <= prod_f1:
        raise SystemExit(
            f"New F1={new_f1:.4f} does not exceed production F1={prod_f1:.4f}. Skipping."
        )

    # Find the latest run with a logged model
    experiment = client.get_experiment_by_name(REG_PARAMS["experiment_name"])
    runs = client.search_runs(
        experiment_ids=[experiment.experiment_id],
        order_by=["start_time DESC"],
        max_results=5,
    )
    train_run = next(
        (r for r in runs if r.data.tags.get("mlflow.runName") == "train"), runs[0]
    )
    model_uri = f"runs:/{train_run.info.run_id}/model"

    mv = mlflow.register_model(model_uri, model_name)
    client.set_registered_model_alias(
        model_name, REG_PARAMS["staging_alias"], mv.version
    )
    print(f"Registered version {mv.version} as '{REG_PARAMS['staging_alias']}'")

    # Auto-promote staging to production when F1 gate passed
    client.set_registered_model_alias(
        model_name, REG_PARAMS["production_alias"], mv.version
    )
    print(f"Promoted version {mv.version} to '{REG_PARAMS['production_alias']}'")


if __name__ == "__main__":
    main()
