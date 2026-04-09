"""
DVC Stage 2: evaluate

Loads ml/data/processed/test.csv, runs the hybrid PII scanner on each row,
compares predicted severity vs expected severity, and saves a JSON report
to ml/reports/evaluation_report.json.
"""

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))

import pandas as pd
from sklearn.metrics import accuracy_score, classification_report

from app.services.leakage_scorer import calculate_risk_score, determine_severity
from app.services.ner_model import load_ner_model
from app.services.pii_scanner import scan_text


async def evaluate() -> None:
    print("Loading NER model...")
    load_ner_model()

    test_path = Path("ml/data/processed/test.csv")
    if not test_path.exists():
        print(f"ERROR: {test_path} not found. Run preprocess first.")
        sys.exit(1)

    test_df = pd.read_csv(test_path)
    y_true: list[str] = []
    y_pred: list[str] = []

    for _, row in test_df.iterrows():
        entities = await scan_text(
            text=str(row["text"]),
            context="general",
            use_transformer=True,
        )
        risk_score = calculate_risk_score(entities)
        predicted_severity = determine_severity(risk_score)
        y_true.append(str(row["expected_severity"]))
        y_pred.append(predicted_severity.value)

    accuracy = accuracy_score(y_true, y_pred)
    report_dict = classification_report(
        y_true,
        y_pred,
        output_dict=True,
        zero_division=0,
    )

    from app.config import get_settings
    settings = get_settings()

    results = {
        "accuracy": round(accuracy, 4),
        "classification_report": report_dict,
        "total_samples": len(test_df),
        "model": f"{settings.ner_model_name} + regex hybrid",
    }

    report_path = Path("ml/reports/evaluation_report.json")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(results, indent=2))

    print(f"\nAccuracy: {accuracy:.2%}")
    print(classification_report(y_true, y_pred, zero_division=0))
    print(f"Report saved to {report_path}")


if __name__ == "__main__":
    asyncio.run(evaluate())
