from __future__ import annotations

"""
DLP scan engine: regex-based entity detection with optional HuggingFace NER.

Public API
----------
load_ner_model()          Synchronous — call via asyncio.to_thread in lifespan.
perform_scan(text, ...)   Returns a ScanResponse.
scan_text(req)            Thin wrapper for text requests.
scan_file(req)            Decodes base64 → text → scan.
scan_network(req)         Scans network payload.
get_model_info()          Returns dict consumed by GET /scan/models/info.
"""

import base64
import logging
import re
import time
import uuid
from typing import Dict, List, Optional, Tuple

from ..models.schemas import (
    DetectedEntity,
    EntityType,
    ScanFileRequest,
    ScanNetworkRequest,
    ScanResponse,
    ScanTextRequest,
    SeverityLevel,
)
from . import ner_model as _ner_model

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Regex patterns — (pattern, EntityType, base_weight)
# ---------------------------------------------------------------------------
_REGEX_PATTERNS: List[Tuple[re.Pattern, EntityType, int]] = [
    (
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        EntityType.SSN,
        35,
    ),
    (
        re.compile(
            r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|"
            r"6(?:011|5[0-9]{2})[0-9]{12}|3(?:0[0-5]|[68][0-9])[0-9]{11}|"
            r"(?:2131|1800|35\d{3})\d{11})\b"
        ),
        EntityType.CREDIT_CARD,
        35,
    ),
    (
        re.compile(
            r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
        ),
        EntityType.EMAIL,
        10,
    ),
    (
        re.compile(
            r"\b(\+\d{1,2}\s?)?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}\b"
        ),
        EntityType.PHONE,
        10,
    ),
    (
        re.compile(
            r"\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
            r"(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}\b"
        ),
        EntityType.IP_ADDRESS,
        10,
    ),
    (
        re.compile(
            r"(?:sk|pk|api[_\-]?key|secret)[_\-]?[a-zA-Z0-9]{24,}",
            re.IGNORECASE,
        ),
        EntityType.API_KEY,
        40,
    ),
    (
        re.compile(
            r"(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,}['\"]",
            re.IGNORECASE,
        ),
        EntityType.PASSWORD,
        40,
    ),
    (
        re.compile(r"\b\d{5}-\d{7}-\d\b"),
        EntityType.CNIC,
        60,
    ),
    (
        re.compile(r"\b\d{8,17}\b"),
        EntityType.BANK_ACCOUNT,
        30,
    ),
    (
        re.compile(
            r"\b[A-Z]{1,2}\d{7,9}\b"  # Passport-style
        ),
        EntityType.PASSPORT,
        30,
    ),
    (
        re.compile(
            r"\b[A-Z]{1,2}\d{6,8}[A-Z]?\b"  # Driver's license
        ),
        EntityType.DRIVERS_LICENSE,
        25,
    ),
    (
        re.compile(
            r"\b\d{1,5}\s+\w+(?:\s+\w+){1,4}\s+(?:Street|St|Avenue|Ave|Road|Rd|"
            r"Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct|Way|Place|Pl)\b",
            re.IGNORECASE,
        ),
        EntityType.ADDRESS,
        15,
    ),
    (
        re.compile(
            r"\b(?:19|20)\d{2}[-/]\d{2}[-/]\d{2}\b"
        ),
        EntityType.DATE_OF_BIRTH,
        25,
    ),
]

# Entities that immediately push severity to CRITICAL
_CRITICAL_TYPES = {EntityType.API_KEY, EntityType.PASSWORD, EntityType.CNIC}

# Entities that push severity to at least HIGH
_HIGH_TYPES = {
    EntityType.SSN,
    EntityType.CREDIT_CARD,
    EntityType.PASSPORT,
    EntityType.BANK_ACCOUNT,
    EntityType.DRIVERS_LICENSE,
}

# ---------------------------------------------------------------------------
# NER state (pipeline lives in ner_model module; these track load status)
# ---------------------------------------------------------------------------
_model_loaded: bool = False
_model_name: str = "dslim/bert-base-NER"
_use_transformer: bool = True

# Mapping from HuggingFace NER labels to EntityType
_NER_LABEL_MAP: Dict[str, EntityType] = {
    "PER": EntityType.CUSTOM,
    "ORG": EntityType.CUSTOM,
    "LOC": EntityType.ADDRESS,
    "MISC": EntityType.CUSTOM,
}

# Names of logical scanner modules (used in health endpoint)
SCANNER_NAMES: List[str] = ["text", "file", "network", "ner"]


def load_ner_model() -> None:
    """Load the HuggingFace NER pipeline (synchronous — run via asyncio.to_thread)."""
    global _model_loaded, _use_transformer

    try:
        from transformers import pipeline  # type: ignore[import]

        _ner_model._pipeline = pipeline(
            "ner",
            model=_model_name,
            aggregation_strategy="simple",
        )
        _model_loaded = True
        _logger.info("NER model '%s' loaded successfully.", _model_name)
    except ImportError:
        _logger.warning(
            "transformers library not installed; running in regex-only mode."
        )
        _use_transformer = False
        _model_loaded = False
    except Exception as exc:  # pragma: no cover
        _logger.error("Failed to load NER model: %s", exc)
        _use_transformer = False
        _model_loaded = False


def get_model_info() -> dict:
    """Return metadata about the currently loaded model."""
    return {
        "ner_model": _model_name,
        "use_transformer": _use_transformer,
        "model_loaded": _model_loaded,
        "regex_patterns_count": len(_REGEX_PATTERNS),
        "entity_types": [e.value for e in EntityType],
    }


# ---------------------------------------------------------------------------
# Core scan logic
# ---------------------------------------------------------------------------

def _regex_scan(text: str) -> List[DetectedEntity]:
    """Run all regex patterns over *text* and return detected entities."""
    entities: List[DetectedEntity] = []
    seen: set = set()  # deduplicate by (type, value)

    for pattern, entity_type, _ in _REGEX_PATTERNS:
        for m in pattern.finditer(text):
            value = m.group(0)
            key = (entity_type, value)
            if key in seen:
                continue
            seen.add(key)

            start, end = m.span()
            ctx_start = max(0, start - 20)
            ctx_end = min(len(text), end + 20)

            entities.append(
                DetectedEntity(
                    entity_type=entity_type,
                    value=value,
                    confidence=0.95,
                    start_pos=start,
                    end_pos=end,
                    context=text[ctx_start:ctx_end],
                )
            )

    return entities


def _ner_scan(text: str) -> List[DetectedEntity]:
    """Run transformer NER via ner_model.run_ner and return additional entities.

    Score filtering (>= 0.85) is applied inside ner_model.run_ner; items
    returned here are already above the threshold.
    """
    entities: List[DetectedEntity] = []
    for item in _ner_model.run_ner(text):
        label = item.get("entity_group", item.get("entity", "MISC")).upper()
        entity_type = _NER_LABEL_MAP.get(label, EntityType.CUSTOM)
        score: float = float(item.get("score", 0.0))
        entities.append(
            DetectedEntity(
                entity_type=entity_type,
                value=item.get("word", ""),
                confidence=round(score, 4),
                start_pos=item.get("start"),
                end_pos=item.get("end"),
                context=None,
            )
        )
    return entities


def _calculate_severity_and_score(
    entities: List[DetectedEntity],
) -> Tuple[SeverityLevel, float]:
    """Derive severity level and 0–100 risk score from detected entities."""
    if not entities:
        return SeverityLevel.SAFE, 0.0

    weight_map: Dict[EntityType, int] = {
        et: w for _, et, w in _REGEX_PATTERNS
    }

    total_weight = 0
    has_critical_type = False
    has_high_type = False

    for entity in entities:
        et = entity.entity_type
        total_weight += weight_map.get(et, 15)
        if et in _CRITICAL_TYPES:
            has_critical_type = True
        elif et in _HIGH_TYPES:
            has_high_type = True

    risk_score = min(float(total_weight), 100.0)

    if has_critical_type or risk_score >= 80:
        return SeverityLevel.CRITICAL, risk_score
    if has_high_type or risk_score >= 50:
        return SeverityLevel.HIGH, risk_score
    if risk_score >= 20:
        return SeverityLevel.MEDIUM, risk_score
    if risk_score > 0:
        return SeverityLevel.LOW, risk_score
    return SeverityLevel.SAFE, 0.0


def _recommended_action(severity: SeverityLevel) -> str:
    actions = {
        SeverityLevel.CRITICAL: "BLOCK",
        SeverityLevel.HIGH: "BLOCK",
        SeverityLevel.MEDIUM: "WARN",
        SeverityLevel.LOW: "LOG",
        SeverityLevel.SAFE: "ALLOW",
    }
    return actions[severity]


def _build_summary(entities: List[DetectedEntity], severity: SeverityLevel) -> str:
    if not entities:
        return "No sensitive data detected."
    counts: Dict[str, int] = {}
    for e in entities:
        counts[e.entity_type.value] = counts.get(e.entity_type.value, 0) + 1
    parts = ", ".join(f"{v} {k}" for k, v in counts.items())
    return f"{severity.value} severity scan detected: {parts}."


def perform_scan(
    text: str,
    scan_id: Optional[str] = None,
) -> ScanResponse:
    """Run entity detection on *text* and return a :class:`ScanResponse`."""
    t0 = time.perf_counter()

    if scan_id is None:
        scan_id = str(uuid.uuid4())

    entities = _regex_scan(text)
    if _model_loaded and _ner_model._pipeline is not None:
        entities.extend(_ner_scan(text))

    # Deduplicate by (type, value) after combining regex + NER
    seen: set = set()
    unique: List[DetectedEntity] = []
    for e in entities:
        key = (e.entity_type, e.value)
        if key not in seen:
            seen.add(key)
            unique.append(e)

    severity, risk_score = _calculate_severity_and_score(unique)
    duration_ms = (time.perf_counter() - t0) * 1000

    return ScanResponse(
        scan_id=scan_id,
        severity=severity,
        risk_score=round(risk_score, 2),
        entities=unique,
        total_entities=len(unique),
        recommended_action=_recommended_action(severity),
        summary=_build_summary(unique, severity),
        scan_duration_ms=round(duration_ms, 3),
    )


# ---------------------------------------------------------------------------
# Request-level wrappers
# ---------------------------------------------------------------------------

def scan_text(req: ScanTextRequest) -> ScanResponse:
    """Scan a plain-text payload."""
    return perform_scan(req.text, scan_id=req.scan_id)


def scan_file(req: ScanFileRequest) -> ScanResponse:
    """Decode a base64-encoded file and scan its text content."""
    try:
        raw_bytes = base64.b64decode(req.content_base64)
        text = raw_bytes.decode("utf-8", errors="replace")
    except Exception as exc:
        raise ValueError(
            f"Could not decode file '{req.filename}': {exc}"
        ) from exc

    return perform_scan(text, scan_id=req.scan_id)


def scan_network(req: ScanNetworkRequest) -> ScanResponse:
    """Scan a network payload string."""
    return perform_scan(req.payload, scan_id=req.scan_id)
