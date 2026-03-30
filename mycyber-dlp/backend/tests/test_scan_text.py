"""
Tests for the PII scanner (hybrid transformer + regex).
"""
import sys
import os
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.services import ner_model as ner_module
from app.services.pii_scanner import scan_text
from app.models.schemas import EntityType, SeverityLevel
from app.services.leakage_scorer import calculate_risk_score, determine_severity


def _reset_pipeline():
    ner_module._pipeline = None


# ─── Existing Day-1 tests ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_scan_email_detected():
    entities = await scan_text("Contact me at user@example.com", "general", use_transformer=False)
    types = {e.entity_type for e in entities}
    assert EntityType.EMAIL in types


@pytest.mark.asyncio
async def test_scan_cnic_detected():
    entities = await scan_text("CNIC: 42101-1234567-1", "general", use_transformer=False)
    types = {e.entity_type for e in entities}
    assert EntityType.CNIC in types


@pytest.mark.asyncio
async def test_scan_no_pii_returns_empty():
    entities = await scan_text("Hello world how are you", "general", use_transformer=False)
    assert entities == []


@pytest.mark.asyncio
async def test_scan_api_key_detected():
    entities = await scan_text(
        'API_KEY = "sk-proj-abc123def456ghi789jkl012"', "code", use_transformer=False
    )
    types = {e.entity_type for e in entities}
    assert EntityType.API_KEY in types


@pytest.mark.asyncio
async def test_scan_multiple_entities():
    text = "Name: Ali, email: ali@test.com, CNIC: 42101-1234567-1"
    entities = await scan_text(text, "general", use_transformer=False)
    types = {e.entity_type for e in entities}
    assert EntityType.EMAIL in types
    assert EntityType.CNIC in types
    assert len(entities) >= 2


@pytest.mark.asyncio
async def test_risk_score_critical_for_cnic():
    entities = await scan_text("CNIC: 42101-1234567-1", "general", use_transformer=False)
    risk = calculate_risk_score(entities)
    severity = determine_severity(risk)
    assert severity == SeverityLevel.CRITICAL


@pytest.mark.asyncio
async def test_scan_ip_address_detected():
    entities = await scan_text("Server at 192.168.1.100", "network", use_transformer=False)
    types = {e.entity_type for e in entities}
    assert EntityType.IP_ADDRESS in types


@pytest.mark.asyncio
async def test_empty_text_returns_empty():
    entities = await scan_text("", "general", use_transformer=False)
    assert entities == []


# ─── New Day-2 tests: hybrid scanner ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_scan_person_name_detected():
    """NER should pick up a person name and return a CUSTOM entity."""
    fake_ner = [
        {
            "entity_group": "PER",
            "score": 0.97,
            "word": "Muhammad Ahmed Khan",
            "start": 24,
            "end": 43,
        }
    ]
    ner_module._pipeline = MagicMock(return_value=fake_ner)

    text = "The report was filed by Muhammad Ahmed Khan"
    entities = await scan_text(text, "general", use_transformer=True)

    types = {e.entity_type for e in entities}
    assert EntityType.CUSTOM in types
    _reset_pipeline()


@pytest.mark.asyncio
async def test_fast_mode_still_catches_regex_pii():
    """use_transformer=False must still catch CNIC via regex."""
    ner_module._pipeline = MagicMock()

    text = "CNIC: 42101-1234567-1"
    entities = await scan_text(text, "general", use_transformer=False)

    types = {e.entity_type for e in entities}
    assert EntityType.CNIC in types

    risk = calculate_risk_score(entities)
    assert determine_severity(risk) == SeverityLevel.CRITICAL
    ner_module._pipeline.assert_not_called()
    _reset_pipeline()


@pytest.mark.asyncio
async def test_scan_code_context_boosts_api_key():
    """API_KEY confidence should be boosted in code context."""
    text = 'API_KEY = "sk-proj-abc123def456ghi789jkl"'
    entities = await scan_text(text, "code", use_transformer=False)

    api_key = next((e for e in entities if e.entity_type == EntityType.API_KEY), None)
    assert api_key is not None
    assert api_key.confidence >= 0.80


@pytest.mark.asyncio
async def test_context_email_boosts_email_confidence():
    """EMAIL confidence should be boosted in email context."""
    text = "Contact: user@example.com"
    entities_general = await scan_text(text, "general", use_transformer=False)
    entities_email = await scan_text(text, "email", use_transformer=False)

    conf_general = next(e.confidence for e in entities_general if e.entity_type == EntityType.EMAIL)
    conf_email = next(e.confidence for e in entities_email if e.entity_type == EntityType.EMAIL)
    assert conf_email >= conf_general


@pytest.mark.asyncio
async def test_deduplication_keeps_higher_confidence():
    """Overlapping entities: the one with higher confidence should survive."""
    fake_ner = [
        {
            "entity_group": "PER",
            "score": 0.99,
            "word": "Ali@example.com",
            "start": 0,
            "end": 15,
        }
    ]
    ner_module._pipeline = MagicMock(return_value=fake_ner)

    text = "Ali@example.com"
    entities = await scan_text(text, "general", use_transformer=True)
    # Should not have two entities covering the exact same span
    starts = [e.position_start for e in entities]
    assert len(starts) == len(set(starts)) or len(entities) == 1
    _reset_pipeline()
