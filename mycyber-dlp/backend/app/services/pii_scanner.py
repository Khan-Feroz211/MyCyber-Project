import re
from app.models.schemas import DetectedEntity, EntityType, SeverityLevel
from app.services.leakage_scorer import ENTITY_SEVERITY_MAP

# Minimum text length (characters) before running the transformer NER.
# Very short strings don't benefit from NER and add latency.
_MIN_TEXT_LENGTH_FOR_NER = 10


def redact_value(value: str) -> str:
    """Redacts a sensitive value, preserving only first and last characters."""
    if len(value) <= 4:
        return "****"
    return value[0] + "*" * (len(value) - 2) + value[-1]


# ─── Regex patterns ──────────────────────────────────────────────────────────

PATTERNS: list[tuple[EntityType, re.Pattern, float]] = [
    (
        EntityType.EMAIL,
        re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
        0.95,
    ),
    (
        EntityType.PHONE,
        re.compile(
            r"(?<!\d)(\+92|0092|0)?[-.\s]?(3\d{2})[-.\s]?\d{7}(?!\d)"
        ),
        0.90,
    ),
    (
        EntityType.CNIC,
        re.compile(r"\b\d{5}-\d{7}-\d\b"),
        0.99,
    ),
    (
        EntityType.CREDIT_CARD,
        re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"),
        0.95,
    ),
    (
        EntityType.IP_ADDRESS,
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
        ),
        0.90,
    ),
    (
        EntityType.API_KEY,
        re.compile(
            r"\b(?:sk-[A-Za-z0-9\-_]{20,}|[A-Za-z0-9]{32,}(?=[^A-Za-z0-9]|$))\b"
        ),
        0.85,
    ),
    (
        EntityType.PASSWORD,
        re.compile(
            r'(?i)(?:password|passwd|pwd|secret)\s*[:=]\s*["\']?([^\s"\']{6,})["\']?'
        ),
        0.90,
    ),
    (
        EntityType.IBAN,
        re.compile(r"\bPK\d{2}[A-Z]{4}[A-Z0-9]{16}\b"),
        0.98,
    ),
    (
        EntityType.URL_WITH_TOKEN,
        re.compile(
            r"https?://[^\s]+(?:token|key|secret|auth|api_key)=[^\s&]+"
        ),
        0.88,
    ),
]


def _scan_regex(text: str) -> list[DetectedEntity]:
    entities: list[DetectedEntity] = []
    for entity_type, pattern, confidence in PATTERNS:
        for match in pattern.finditer(text):
            matched_text = match.group(0)
            entities.append(
                DetectedEntity(
                    entity_type=entity_type,
                    value=matched_text,
                    redacted_value=redact_value(matched_text),
                    confidence=confidence,
                    severity=ENTITY_SEVERITY_MAP.get(
                        entity_type, SeverityLevel.MEDIUM
                    ),
                    position_start=match.start(),
                    position_end=match.end(),
                )
            )
    return entities


def _entities_overlap(a: DetectedEntity, b: DetectedEntity) -> bool:
    return a.position_start < b.position_end and b.position_start < a.position_end


def _deduplicate(entities: list[DetectedEntity]) -> list[DetectedEntity]:
    """
    Deduplicates overlapping entities, keeping the one with higher confidence.
    """
    entities = sorted(entities, key=lambda e: (e.position_start, -e.confidence))
    result: list[DetectedEntity] = []
    for entity in entities:
        dominated = False
        for kept in result:
            if _entities_overlap(entity, kept) and kept.confidence >= entity.confidence:
                dominated = True
                break
        if not dominated:
            result = [
                k for k in result
                if not (_entities_overlap(k, entity) and entity.confidence > k.confidence)
            ]
            result.append(entity)
    return sorted(result, key=lambda e: e.position_start)


def _apply_context_boost(
    entities: list[DetectedEntity], context: str
) -> list[DetectedEntity]:
    boosted: list[DetectedEntity] = []
    for e in entities:
        conf = e.confidence
        if context == "code" and e.entity_type in (EntityType.API_KEY, EntityType.PASSWORD):
            conf = min(conf + 0.05, 1.0)
        elif context == "email" and e.entity_type == EntityType.EMAIL:
            conf = min(conf + 0.05, 1.0)
        elif context == "network" and e.entity_type == EntityType.IP_ADDRESS:
            conf = min(conf + 0.05, 1.0)
        boosted.append(e.model_copy(update={"confidence": conf}))
    return boosted


async def scan_text(
    text: str,
    context: str,
    use_transformer: bool = True,
) -> list[DetectedEntity]:
    """
    HYBRID scanning pipeline:

    Step 1 — Regex scan (fast, high precision for structured PII).
    Step 2 — Transformer NER scan (catches unstructured PII).
    Step 3 — Merge and deduplicate overlapping entities.
    Step 4 — Context-aware confidence boosting.
    """
    import asyncio
    from app.services.ner_model import run_ner, convert_ner_to_entities

    # Step 1: regex
    regex_entities = _scan_regex(text)

    # Step 2: transformer NER
    ner_entities: list[DetectedEntity] = []
    if use_transformer and len(text) > _MIN_TEXT_LENGTH_FOR_NER:
        ner_results = await asyncio.to_thread(run_ner, text)
        ner_entities = convert_ner_to_entities(ner_results, text)

    # Step 3: merge and deduplicate
    combined = regex_entities + ner_entities
    deduped = _deduplicate(combined)

    # Step 4: context boost
    return _apply_context_boost(deduped, context)
