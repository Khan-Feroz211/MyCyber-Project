from __future__ import annotations

import asyncio
import functools
import time
from typing import Callable

import mlflow

from app.config import get_settings
from app.mlops.logger import get_logger

logger = get_logger(__name__)


def setup_mlflow() -> None:
    """
    Configure MLflow tracking URI and experiment.
    Called once at application startup in lifespan.
    Experiment name: "mycyber-dlp-scans"
    Logs warning if MLflow server unreachable —
    never raises, never breaks the app.
    """
    try:
        settings = get_settings()
        mlflow.set_tracking_uri(settings.mlflow_tracking_uri)
        mlflow.set_experiment("mycyber-dlp-scans")
        logger.info(
            "MLflow configured",
            extra={"endpoint": settings.mlflow_tracking_uri},
        )
    except Exception as exc:
        logger.warning(
            "MLflow setup failed — continuing without",
            extra={"message": str(exc)},
        )


def track_scan(scan_type: str) -> Callable:
    """
    Decorator for scan service functions (sync or async).
    Logs each scan call as an MLflow run with:

    Params:
      scan_type       — text / file / network
      model_version   — "hybrid-v1" (regex + NER)
      use_transformer — from settings

    Metrics:
      latency_ms      — wall clock time
      entity_count    — number of entities found
      risk_score      — 0.0 to 100.0
      text_length     — input character count

    Tags:
      severity           — CRITICAL/HIGH/MEDIUM/LOW/SAFE
      recommended_action — BLOCK/WARN/ALLOW
      status             — success / error

    Never lets MLflow failure break the actual scan.
    Uses nested=True so runs can be nested.
    """

    def decorator(func: Callable) -> Callable:
        def _log_to_mlflow(result, latency_ms: float, status: str) -> None:
            try:
                with mlflow.start_run(nested=True):
                    mlflow.log_params(
                        {
                            "scan_type": scan_type,
                            "model_version": "hybrid-v1",
                        }
                    )
                    if result is not None:
                        mlflow.log_metrics(
                            {
                                "latency_ms": latency_ms,
                                "entity_count": result.total_entities,
                                "risk_score": result.risk_score,
                            }
                        )
                        mlflow.set_tags(
                            {
                                "severity": result.severity.value,
                                "recommended_action": result.recommended_action,
                                "status": status,
                            }
                        )
                    else:
                        mlflow.set_tags({"status": status})
            except Exception as mlflow_err:
                logger.warning(
                    "MLflow tracking failed",
                    extra={"message": str(mlflow_err)},
                )

        if asyncio.iscoroutinefunction(func):
            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                start = time.perf_counter()
                status = "success"
                result = None
                try:
                    result = await func(*args, **kwargs)
                    return result
                except Exception:
                    status = "error"
                    raise
                finally:
                    latency_ms = round((time.perf_counter() - start) * 1000, 1)
                    _log_to_mlflow(result, latency_ms, status)

            return async_wrapper
        else:
            @functools.wraps(func)
            def sync_wrapper(*args, **kwargs):
                start = time.perf_counter()
                status = "success"
                result = None
                try:
                    result = func(*args, **kwargs)
                    return result
                except Exception:
                    status = "error"
                    raise
                finally:
                    latency_ms = round((time.perf_counter() - start) * 1000, 1)
                    _log_to_mlflow(result, latency_ms, status)

            return sync_wrapper

    return decorator
