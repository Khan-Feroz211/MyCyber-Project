import logging
import time
from typing import Optional

from transformers import pipeline as _hf_pipeline

from app.models.schemas import DetectedEntity, EntityType, SeverityLevel
from app.services.leakage_scorer import ENTITY_SEVERITY_MAP

logger = logging.getLogger(__name__)

MODEL_NAME = "dslim/bert-base-NER"
MIN_NER_CONFIDENCE = 0.85

# chunk sizes (in whitespace-split tokens, approximated as words)
_CHUNK_SIZE = 400
_CHUNK_OVERLAP = 50

_pipeline: Optional[object] = None

NER_TO_ENTITY_TYPE: dict[str, EntityType] = {
    "PER": EntityType.CUSTOM,
    "ORG": EntityType.CUSTOM,
    "LOC": EntityType.CUSTOM,
    "MISC": EntityType.CUSTOM,
}


def load_ner_model() -> None:
    """
    Loads the HuggingFace NER pipeline once at startup.
    Called from the app lifespan in main.py via asyncio.to_thread().
    Stores the result in the module-level _pipeline singleton.
    """
    global _pipeline
    if _pipeline is not None:
        return

    t0 = time.time()
    _pipeline = _hf_pipeline(
        "ner",
        model=MODEL_NAME,
        aggregation_strategy="simple",
        device=-1,
    )
    elapsed_ms = int((time.time() - t0) * 1000)
    logger.info("NER model '%s' loaded in %d ms", MODEL_NAME, elapsed_ms)


def get_ner_pipeline():
    """
    Returns the loaded NER pipeline singleton.
    Raises RuntimeError if load_ner_model() has not been called.
    """
    if _pipeline is None:
        raise RuntimeError(
            "NER model is not loaded. Call load_ner_model() first."
        )
    return _pipeline


def _split_into_chunks(words: list[str]) -> list[tuple[list[str], int]]:
    """
    Splits a word list into overlapping chunks.
    Returns list of (chunk_words, start_word_index).
    """
    chunks: list[tuple[list[str], int]] = []
    start = 0
    while start < len(words):
        end = min(start + _CHUNK_SIZE, len(words))
        chunks.append((words[start:end], start))
        if end == len(words):
            break
        start += _CHUNK_SIZE - _CHUNK_OVERLAP
    return chunks


def run_ner(text: str) -> list[dict]:
    """
    Runs NER inference on text, handling long texts via chunking.
    Splits text into ~400-word chunks with 50-word overlap, runs
    inference on each chunk, then merges results back to original
    character offsets. Deduplicates entities from overlapping chunks.
    """
    import re

    pipe = get_ner_pipeline()

    # Use regex split to get exact character positions of each word
    word_spans = [(m.start(), m.end()) for m in re.finditer(r"\S+", text)]
    if not word_spans:
        return []

    words = [text[s:e] for s, e in word_spans]
    word_char_starts = [s for s, _ in word_spans]

    chunks = _split_into_chunks(words)
    all_entities: list[dict] = []
    seen_spans: set[tuple[int, int]] = set()

    for chunk_words, chunk_word_start in chunks:
        chunk_text = " ".join(chunk_words)
        chunk_char_offset = word_char_starts[chunk_word_start]

        results = pipe(chunk_text)
        for ent in results:
            orig_start = chunk_char_offset + ent["start"]
            orig_end = chunk_char_offset + ent["end"]
            span = (orig_start, orig_end)
            if span in seen_spans:
                continue
            seen_spans.add(span)
            all_entities.append(
                {
                    "entity_group": ent["entity_group"],
                    "score": ent["score"],
                    "word": ent["word"],
                    "start": orig_start,
                    "end": orig_end,
                }
            )

    return all_entities


def _redact_value(value: str) -> str:
    if len(value) <= 4:
        return "****"
    return value[0] + "*" * (len(value) - 2) + value[-1]


def convert_ner_to_entities(
    ner_results: list[dict],
    text: str,
) -> list[DetectedEntity]:
    """
    Converts raw HuggingFace NER output to DetectedEntity objects.
    Filters out results below MIN_NER_CONFIDENCE.
    """
    entities: list[DetectedEntity] = []
    for result in ner_results:
        score: float = result.get("score", 0.0)
        if score < MIN_NER_CONFIDENCE:
            continue

        group: str = result.get("entity_group", "MISC")
        entity_type = NER_TO_ENTITY_TYPE.get(group, EntityType.CUSTOM)
        word: str = result.get("word", "")
        start: int = result.get("start", 0)
        end: int = result.get("end", len(word))

        entities.append(
            DetectedEntity(
                entity_type=entity_type,
                value=word,
                redacted_value=_redact_value(word),
                confidence=round(score, 4),
                severity=ENTITY_SEVERITY_MAP.get(entity_type, SeverityLevel.MEDIUM),
                position_start=start,
                position_end=end,
            )
        )
    return entities
