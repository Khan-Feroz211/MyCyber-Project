"""Tests for policy engine."""
import pytest
from services.policy_engine.main import evaluate_policy, Decision


def test_allow_clean():
    result = evaluate_policy({
        "scan_id": "s1", "tenant_id": "t1",
        "label": "CLEAN", "confidence": 0.98, "pii_types": [],
    })
    assert result.decision == Decision.ALLOW


def test_block_high_risk():
    result = evaluate_policy({
        "scan_id": "s2", "tenant_id": "t1",
        "label": "SENSITIVE_HIGH", "confidence": 0.92, "pii_types": ["ssn"],
    })
    assert result.decision == Decision.BLOCK


def test_warn_low_risk():
    result = evaluate_policy({
        "scan_id": "s3", "tenant_id": "t1",
        "label": "SENSITIVE_LOW", "confidence": 0.75, "pii_types": ["email"],
    })
    assert result.decision == Decision.WARN


def test_warn_high_risk_low_confidence():
    result = evaluate_policy({
        "scan_id": "s4", "tenant_id": "t1",
        "label": "SENSITIVE_HIGH", "confidence": 0.70, "pii_types": ["credit_card"],
    })
    assert result.decision == Decision.WARN
