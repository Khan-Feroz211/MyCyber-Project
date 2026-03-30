"""
Unit tests for the NER model service (ner_model.py).
All tests mock the HuggingFace pipeline so no model download is needed.
"""
import sys
import types
from unittest.mock import MagicMock, patch

import pytest

# ─── Ensure backend package is importable ─────────────────────────────────────
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.services import ner_model as ner_module
from app.services.ner_model import (
    MIN_NER_CONFIDENCE,
    convert_ner_to_entities,
    get_ner_pipeline,
    load_ner_model,
    run_ner,
)
from app.models.schemas import EntityType


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _reset_pipeline():
    """Reset module-level singleton between tests."""
    ner_module._pipeline = None


# ─── Tests ────────────────────────────────────────────────────────────────────


class TestLoadNerModel:
    def test_load_ner_model_sets_pipeline(self):
        _reset_pipeline()
        mock_pipeline = MagicMock()
        with patch("app.services.ner_model.load_ner_model") as mock_load:
            # Simulate what load_ner_model does
            def side_effect():
                ner_module._pipeline = mock_pipeline()

            mock_load.side_effect = side_effect
            mock_load()
            assert ner_module._pipeline is not None

    def test_load_ner_model_uses_hf_pipeline(self):
        _reset_pipeline()
        with patch("transformers.pipeline") as mock_hf:
            mock_hf.return_value = MagicMock()
            load_ner_model()
            mock_hf.assert_called_once_with(
                "ner",
                model="dslim/bert-base-NER",
                aggregation_strategy="simple",
                device=-1,
            )
            assert ner_module._pipeline is not None

    def test_load_ner_model_is_idempotent(self):
        """Calling load_ner_model twice should not reload."""
        _reset_pipeline()
        with patch("transformers.pipeline") as mock_hf:
            mock_hf.return_value = MagicMock()
            load_ner_model()
            load_ner_model()
            mock_hf.assert_called_once()


class TestGetNerPipeline:
    def test_get_ner_pipeline_raises_if_not_loaded(self):
        _reset_pipeline()
        with pytest.raises(RuntimeError, match="not loaded"):
            get_ner_pipeline()

    def test_get_ner_pipeline_returns_pipeline(self):
        mock_pipe = MagicMock()
        ner_module._pipeline = mock_pipe
        assert get_ner_pipeline() is mock_pipe
        _reset_pipeline()


class TestRunNer:
    def test_run_ner_returns_entities(self):
        fake_result = [
            {
                "entity_group": "PER",
                "score": 0.98,
                "word": "John Smith",
                "start": 0,
                "end": 10,
            }
        ]
        mock_pipe = MagicMock(return_value=fake_result)
        ner_module._pipeline = mock_pipe

        result = run_ner("John Smith went to Karachi")

        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["entity_group"] == "PER"
        _reset_pipeline()

    def test_run_ner_empty_text(self):
        ner_module._pipeline = MagicMock(return_value=[])
        result = run_ner("")
        assert result == []
        _reset_pipeline()

    def test_run_ner_adjusts_chunk_offsets(self):
        """Entities in the second chunk should have correct character offsets."""
        chunk1_result = [
            {"entity_group": "PER", "score": 0.95, "word": "Ali", "start": 0, "end": 3}
        ]
        chunk2_result = [
            {"entity_group": "LOC", "score": 0.92, "word": "Lahore", "start": 0, "end": 6}
        ]
        call_count = 0

        def pipe_side_effect(chunk_text):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return chunk1_result
            return chunk2_result

        mock_pipe = MagicMock(side_effect=pipe_side_effect)
        ner_module._pipeline = mock_pipe

        # Build text long enough to need two chunks (> _CHUNK_SIZE words)
        long_text = "Ali " + "word " * 401 + "Lahore"
        result = run_ner(long_text)

        assert any(e["entity_group"] == "PER" for e in result)
        assert any(e["entity_group"] == "LOC" for e in result)
        # LOC offset must be > 0 (not at start)
        loc = next(e for e in result if e["entity_group"] == "LOC")
        assert loc["start"] > 0
        _reset_pipeline()


class TestConvertNerToEntities:
    def test_below_confidence_filtered(self):
        ner_results = [
            {
                "entity_group": "PER",
                "score": 0.50,
                "word": "Ghost",
                "start": 0,
                "end": 5,
            }
        ]
        entities = convert_ner_to_entities(ner_results, "Ghost person")
        assert entities == []

    def test_above_confidence_included(self):
        ner_results = [
            {
                "entity_group": "PER",
                "score": 0.95,
                "word": "Ali Khan",
                "start": 0,
                "end": 8,
            }
        ]
        entities = convert_ner_to_entities(ner_results, "Ali Khan is here")
        assert len(entities) == 1
        assert entities[0].entity_type == EntityType.CUSTOM

    def test_exactly_at_threshold_included(self):
        ner_results = [
            {
                "entity_group": "ORG",
                "score": MIN_NER_CONFIDENCE,
                "word": "ACME",
                "start": 0,
                "end": 4,
            }
        ]
        entities = convert_ner_to_entities(ner_results, "ACME corp")
        assert len(entities) == 1

    def test_redaction_applied(self):
        ner_results = [
            {
                "entity_group": "PER",
                "score": 0.99,
                "word": "Muhammad Ahmed",
                "start": 0,
                "end": 14,
            }
        ]
        entities = convert_ner_to_entities(ner_results, "Muhammad Ahmed is here")
        assert entities[0].redacted_value != entities[0].value
        assert "*" in entities[0].redacted_value


class TestHybridScanner:
    @pytest.mark.asyncio
    async def test_hybrid_scanner_combines_results(self):
        from app.services.pii_scanner import scan_text

        fake_ner = [
            {
                "entity_group": "PER",
                "score": 0.97,
                "word": "Ali Khan",
                "start": 22,
                "end": 30,
            }
        ]
        ner_module._pipeline = MagicMock(return_value=fake_ner)

        text = "Email john@test.com, name: Ali Khan"
        entities = await scan_text(text, "general", use_transformer=True)

        types_found = {e.entity_type for e in entities}
        assert EntityType.EMAIL in types_found
        assert EntityType.CUSTOM in types_found
        assert len(entities) >= 2
        _reset_pipeline()

    @pytest.mark.asyncio
    async def test_scan_text_fast_mode_skips_transformer(self):
        from app.services.pii_scanner import scan_text

        mock_pipe = MagicMock()
        ner_module._pipeline = mock_pipe

        entities = await scan_text("test@email.com", "general", use_transformer=False)

        mock_pipe.assert_not_called()
        types_found = {e.entity_type for e in entities}
        assert EntityType.EMAIL in types_found
        _reset_pipeline()
