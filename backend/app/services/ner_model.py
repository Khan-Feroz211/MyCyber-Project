from __future__ import annotations

"""Thin NER-model wrapper used by the scanner engine.

Keeping the pipeline in its own module allows tests to mock just two names:
    app.services.ner_model._pipeline
    app.services.ner_model.run_ner

without touching any of the regex / scoring logic in scanner.py.
"""

import logging
from typing import Any, Dict, List, Optional

_logger = logging.getLogger(__name__)

# Populated by scanner.load_ner_model() at application startup.
_pipeline: Optional[object] = None


def run_ner(text: str) -> List[Dict[str, Any]]:
    """Run the NER pipeline over *text*.

    Returns a list of raw result dicts (HuggingFace format) with at least
    ``entity_group``, ``score``, ``word``, ``start``, and ``end`` keys.
    Only results with confidence >= 0.85 are returned.
    Returns an empty list when the pipeline is not loaded or on error.
    """
    if _pipeline is None:
        return []
    try:
        results = _pipeline(text[:512])  # BERT-family 512-token limit
        return [r for r in results if float(r.get("score", 0.0)) >= 0.85]
    except Exception as exc:  # pragma: no cover
        _logger.warning("NER pipeline call failed: %s", exc)
        return []
