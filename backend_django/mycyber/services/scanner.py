"""DLP scan engine (Django port of ``backend/app/services/scanner.py``).

Regex-based entity detection with optional HuggingFace NER.  All heavy
third-party imports (transformers, PIL, pdfplumber, python-docx, pytesseract,
tika) are performed lazily so importing this module is cheap and safe in
environments where those packages are not installed (e.g. the test / CI
environment).

Public API
----------
EntityType, SeverityLevel     enums
DetectedEntity                dataclass with .to_dict()
perform_scan(text, scan_id)   -> dict (ScanResponse-shaped)
scan_text(req), scan_file(req), scan_network(req)
get_model_info()              -> dict
load_ner_model()              -> None (lazy, best-effort)
SCANNER_NAMES                 list
"""
from __future__ import annotations

import base64
import binascii
import io
import logging
import os
import re
import time
import uuid
import zipfile
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums / entities
# ---------------------------------------------------------------------------


class EntityType(str, Enum):
    SSN = "SSN"
    CREDIT_CARD = "CREDIT_CARD"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    IP_ADDRESS = "IP_ADDRESS"
    API_KEY = "API_KEY"
    PASSWORD = "PASSWORD"
    DATE_OF_BIRTH = "DATE_OF_BIRTH"
    ADDRESS = "ADDRESS"
    PASSPORT = "PASSPORT"
    DRIVERS_LICENSE = "DRIVERS_LICENSE"
    BANK_ACCOUNT = "BANK_ACCOUNT"
    CNIC = "CNIC"
    SQL_INJECTION = "SQL_INJECTION"
    PROMPT_INJECTION = "PROMPT_INJECTION"
    CUSTOM = "CUSTOM"


class SeverityLevel(str, Enum):
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class DetectedEntity:
    entity_type: EntityType
    value: str
    confidence: float = 0.95
    start_pos: Optional[int] = None
    end_pos: Optional[int] = None
    context: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "entity_type": self.entity_type.value,
            "value": self.value,
            "confidence": self.confidence,
            "start_pos": self.start_pos,
            "end_pos": self.end_pos,
            "context": self.context,
        }


# ---------------------------------------------------------------------------
# Regex patterns — (pattern, EntityType, base_weight)  [ported verbatim]
# ---------------------------------------------------------------------------

_REGEX_PATTERNS = [
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), EntityType.SSN, 35),
    (
        re.compile(
            r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|"
            r"6(?:011|5[0-9]{2})[0-9]{12}|3(?:0[0-5]|[68][0-9])[0-9]{11}|"
            r"(?:2131|1800|35\d{3})\d{11})\b"
        ),
        EntityType.CREDIT_CARD,
        35,
    ),
    (re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), EntityType.EMAIL, 10),
    (re.compile(r"\b(\+\d{1,2}\s?)?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}\b"), EntityType.PHONE, 10),
    (
        re.compile(
            r"\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
            r"(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}\b"
        ),
        EntityType.IP_ADDRESS,
        10,
    ),
    (
        re.compile(r"(?:sk|pk|api[_\-]?key|secret)[_\-]?[a-zA-Z0-9]{24,}", re.IGNORECASE),
        EntityType.API_KEY,
        40,
    ),
    (
        re.compile(r"(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,}['\"]", re.IGNORECASE),
        EntityType.PASSWORD,
        40,
    ),
    (re.compile(r"\b\d{5}-\d{7}-\d\b"), EntityType.CNIC, 60),
    (re.compile(r"\b\d{13}\b"), EntityType.CNIC, 55),
    (re.compile(r"\b\d{8,17}\b"), EntityType.BANK_ACCOUNT, 30),
    (re.compile(r"\b\d{7}-\d\b"), EntityType.CUSTOM, 45),
    (re.compile(r"\bPK[0-9]{2}[0-9]{16,20}\b"), EntityType.BANK_ACCOUNT, 60),
    (re.compile(r"\b03[0-9]{2}-[0-9]{7}\b"), EntityType.PHONE, 25),
    (re.compile(r"\b03[0-9]{9}\b"), EntityType.PHONE, 25),
    (re.compile(r"\b[A-Z]{1,2}[0-9]{7}\b"), EntityType.PASSPORT, 35),
    (re.compile(r"\b\d{10,14}\b"), EntityType.BANK_ACCOUNT, 35),
    (re.compile(r"\b[A-Z]{1,2}\d{7,9}\b"), EntityType.PASSPORT, 30),
    (re.compile(r"\b[A-Z]{1,2}\d{6,8}[A-Z]?\b"), EntityType.DRIVERS_LICENSE, 25),
    (
        re.compile(
            r"\b\d{1,5}\s+\w+(?:\s+\w+){1,4}\s+(?:Street|St|Avenue|Ave|Road|Rd|"
            r"Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct|Way|Place|Pl)\b",
            re.IGNORECASE,
        ),
        EntityType.ADDRESS,
        15,
    ),
    (re.compile(r"\b(?:19|20)\d{2}[-/]\d{2}[-/]\d{2}\b"), EntityType.DATE_OF_BIRTH, 25),
    (
        re.compile(
            r"(?:"
            r"(?:--|#|/\*).*$"
            r"|'\s*(?:OR|AND)\s*'?\d"
            r"|\bUNION\b.*\bSELECT\b"
            r"|\bDROP\s+TABLE\b"
            r"|\bINSERT\s+INTO\b"
            r"|\bDELETE\s+FROM\b"
            r"|\bEXEC(?:UTE)?\s*\("
            r"|'\s*;\s*(?:DROP|DELETE|UPDATE|INSERT)"
            r"|\bSLEEP\s*\(\d+\)"
            r"|\bBENCHMARK\s*\("
            r"|\bWAITFOR\s+DELAY\b"
            r"|\bxp_cmdshell\b"
            r"|\bINFORMATION_SCHEMA\b"
            r")",
            re.IGNORECASE | re.MULTILINE,
        ),
        EntityType.SQL_INJECTION,
        60,
    ),
    (
        re.compile(
            r"(?:"
            r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?"
            r"|disregard\s+(?:all\s+)?(?:previous|prior|system)\s+(?:prompt|instructions?)"
            r"|you\s+are\s+now\s+(?:a\s+)?(?:DAN|jailbreak|evil|uncensored)"
            r"|act\s+as\s+(?:if\s+)?(?:you\s+(?:have\s+)?no\s+restrictions?|an?\s+unrestricted)"
            r"|(?:forget|override)\s+(?:your\s+)?(?:previous\s+)?instructions?"
            r"|reveal\s+(?:your\s+)?system\s+prompt"
            r"|do\s+anything\s+now"
            r"|jailbreak"
            r"|prompt\s+injection"
            r")",
            re.IGNORECASE,
        ),
        EntityType.PROMPT_INJECTION,
        70,
    ),
]

_WEIGHT_MAP = {et: w for _, et, w in _REGEX_PATTERNS}

_CRITICAL_TYPES = {
    EntityType.API_KEY,
    EntityType.PASSWORD,
    EntityType.CNIC,
    EntityType.SQL_INJECTION,
    EntityType.PROMPT_INJECTION,
}
_HIGH_TYPES = {
    EntityType.SSN,
    EntityType.CREDIT_CARD,
    EntityType.PASSPORT,
    EntityType.BANK_ACCOUNT,
    EntityType.DRIVERS_LICENSE,
}

# NER state (pipeline lives in ner_model module; tracked lazily)
_model_loaded = False
_model_name = "dslim/bert-base-NER"
_use_transformer = True

SCANNER_NAMES = ["text", "file", "network", "ner"]


# ---------------------------------------------------------------------------
# NER (lazy)
# ---------------------------------------------------------------------------


def load_ner_model() -> None:
    """Load the HuggingFace NER pipeline (synchronous; best-effort)."""
    global _model_loaded, _use_transformer
    try:
        from transformers import pipeline  # type: ignore

        import mycyber.services.ner_model as _ner_model  # noqa: F401

        _ner_model._pipeline = pipeline("ner", model=_model_name, aggregation_strategy="simple")
        _model_loaded = True
        _logger.info("NER model '%s' loaded successfully.", _model_name)
    except ImportError:
        _use_transformer = False
        _model_loaded = False
        _logger.warning("transformers not installed; running regex-only mode.")
    except Exception as exc:  # pragma: no cover
        _use_transformer = False
        _model_loaded = False
        _logger.error("Failed to load NER model: %s", exc)


def get_model_info() -> dict:
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


def _regex_scan(text: str) -> list[DetectedEntity]:
    entities: list[DetectedEntity] = []
    seen: set[tuple[EntityType, str]] = set()
    for pattern, entity_type, _weight in _REGEX_PATTERNS:
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


def _ner_scan(text: str) -> list[DetectedEntity]:
    """Run transformer NER (if loaded) and return additional entities."""
    import mycyber.services.ner_model as _ner_model  # type: ignore

    if not _model_loaded or getattr(_ner_model, "_pipeline", None) is None:
        return []
    entities: list[DetectedEntity] = []
    _NER_LABEL_MAP = {
        "PER": EntityType.CUSTOM,
        "ORG": EntityType.CUSTOM,
        "LOC": EntityType.ADDRESS,
        "MISC": EntityType.CUSTOM,
    }
    for item in _ner_model.run_ner(text):
        label = item.get("entity_group", item.get("entity", "MISC")).upper()
        entity_type = _NER_LABEL_MAP.get(label, EntityType.CUSTOM)
        score = float(item.get("score", 0.0))
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


def _calc_severity(entities: list[DetectedEntity]) -> tuple[SeverityLevel, float]:
    if not entities:
        return SeverityLevel.SAFE, 0.0
    total_weight = 0
    has_critical = False
    has_high = False
    for entity in entities:
        et = entity.entity_type
        total_weight += _WEIGHT_MAP.get(et, 15)
        if et in _CRITICAL_TYPES:
            has_critical = True
        elif et in _HIGH_TYPES:
            has_high = True
    risk_score = min(float(total_weight), 100.0)
    if has_critical or risk_score >= 80:
        return SeverityLevel.CRITICAL, risk_score
    if has_high or risk_score >= 50:
        return SeverityLevel.HIGH, risk_score
    if risk_score >= 20:
        return SeverityLevel.MEDIUM, risk_score
    if risk_score > 0:
        return SeverityLevel.LOW, risk_score
    return SeverityLevel.SAFE, 0.0


def _recommended_action(severity: SeverityLevel) -> str:
    return {
        SeverityLevel.CRITICAL: "BLOCK",
        SeverityLevel.HIGH: "BLOCK",
        SeverityLevel.MEDIUM: "WARN",
        SeverityLevel.LOW: "LOG",
        SeverityLevel.SAFE: "ALLOW",
    }[severity]


def _build_summary(entities: list[DetectedEntity], severity: SeverityLevel) -> str:
    if not entities:
        return "No sensitive data detected."
    counts: dict[str, int] = {}
    for e in entities:
        counts[e.entity_type.value] = counts.get(e.entity_type.value, 0) + 1
    parts = ", ".join(f"{v} {k}" for k, v in counts.items())
    return f"{severity.value} severity scan detected: {parts}."


def perform_scan(text: str, scan_id: Optional[str] = None) -> dict:
    """Run entity detection on *text* and return a ScanResponse-shaped dict."""
    t0 = time.perf_counter()
    if scan_id is None:
        scan_id = str(uuid.uuid4())

    entities = _regex_scan(text)
    if _model_loaded:
        entities.extend(_ner_scan(text))

    # Deduplicate by (type, value)
    seen: set[tuple[EntityType, str]] = set()
    unique: list[DetectedEntity] = []
    for e in entities:
        k = (e.entity_type, e.value)
        if k not in seen:
            seen.add(k)
            unique.append(e)

    severity, risk_score = _calc_severity(unique)
    duration_ms = (time.perf_counter() - t0) * 1000
    return {
        "scan_id": scan_id,
        "severity": severity.value,
        "risk_score": round(risk_score, 2),
        "entities": [e.to_dict() for e in unique],
        "total_entities": len(unique),
        "recommended_action": _recommended_action(severity),
        "summary": _build_summary(unique, severity),
        "scan_duration_ms": round(duration_ms, 3),
    }


# ---------------------------------------------------------------------------
# Request-level wrappers
# ---------------------------------------------------------------------------


def scan_text(req: dict) -> dict:
    """Scan a plain-text payload (``{"text": ..., "scan_id": ...}``)."""
    return perform_scan(req["text"], scan_id=req.get("scan_id"))


def scan_file(req: dict) -> dict:
    """Decode a base64-encoded file and scan its text content."""
    raw_bytes = base64.b64decode(req["content_base64"])
    text = _extract_text_from_bytes(raw_bytes, req.get("filename", "file"))
    result = perform_scan(text, scan_id=req.get("scan_id"))
    result["filename"] = req.get("filename")
    return result


def scan_network(req: dict) -> dict:
    """Scan a network payload (`{"payload": ..., "source_ip": ...}``)."""
    result = perform_scan(req["payload"], scan_id=req.get("scan_id"))
    result["source_ip"] = req.get("source_ip")
    return result


# ---------------------------------------------------------------------------
# File text extraction (import-safe — optional backends are lazy)
# ---------------------------------------------------------------------------


def _extract_text_from_bytes(data: bytes, filename: str) -> str:
    """Best-effort text extraction from raw bytes.

    Strategies (in order): UTF-8 decode, ZIP, PDF (pdfplumber), DOCX
    (python-docx), image OCR (pytesseract+PIL).  Each optional backend is
    imported lazily; missing backends are skipped.
    """
    # 1) UTF-8 decode
    try:
        s = data.decode("utf-8")
        if s.strip():
            return s
    except UnicodeDecodeError:
        pass

    # 2) ZIP archive
    try:
        if data[:4] == b"PK\x03\x04":
            parts: list[str] = []
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for name in z.namelist():
                    try:
                        child = z.read(name)
                        parts.append(_extract_text_from_bytes(child, name))
                    except RuntimeError:
                        parts.append(f"[ENCRYPTED_FILE:{name}]")
            return "\n".join(p for p in parts if p)
    except Exception:
        pass

    # 3) PDF (pdfplumber)
    try:
        import pdfplumber  # type: ignore

        with pdfplumber.open(io.BytesIO(data)) as pdf:
            return "\n".join(page.extract_text() or "" for page in pdf.pages)
    except Exception:
        pass

    # 4) DOCX (python-docx)
    try:
        import docx  # type: ignore

        text_parts = [p.text for p in docx.Document(io.BytesIO(data)).paragraphs]
        return "\n".join(text_parts)
    except Exception:
        pass

    # 5) Image OCR (pytesseract + PIL)
    try:
        from PIL import Image  # type: ignore
        import pytesseract  # type: ignore

        img = Image.open(io.BytesIO(data))
        return pytesseract.image_to_string(img)
    except Exception:
        pass

    # 6) Fallback: latin-1 decode so something is always returned
    try:
        return data.decode("latin-1")
    except Exception:
        return ""
