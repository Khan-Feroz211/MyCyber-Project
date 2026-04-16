# ADR 001: Hybrid PII Scanner Architecture

**Status:** Accepted
**Date:** 2025
**Author:** Feroz Khan

---

## Context

MyCyber DLP needs to detect personally identifiable information (PII) and sensitive data in
text, files, and network payloads with high accuracy and low latency. Two primary approaches
were considered:

1. **Pure regex** — deterministic pattern matching for structured data (CNIC, email, credit card, IBAN, etc.)
2. **Pure ML model** — transformer-based Named Entity Recognition (NER) for unstructured text

Neither approach alone satisfies all requirements:

- Pure regex cannot detect unstructured PII such as a person's name mentioned in a sentence.
- Pure ML cannot reliably detect Pakistan-specific structured identifiers (e.g. CNIC format
  `42101-1234567-1`) and produces false positives without domain-specific rules.

---

## Decision

Use a **hybrid approach**: regex patterns run first (fast, high-precision for structured PII),
followed by a HuggingFace NER transformer (`dslim/bert-base-NER`) that catches unstructured PII
the regex engine misses.

The pipeline is:

```
Input text
    │
    ▼
Regex Engine (9 patterns, microseconds)
    │  matches: CNIC, email, credit card, IBAN,
    │           API key, password, IP, URL-token, phone
    ▼
HuggingFace NER  (optional, ~200 ms, skipped when fast_mode=true)
    │  catches: PERSON, ORG, LOC in context
    ▼
Deduplication   (merge overlapping spans, keep highest confidence)
    │
    ▼
Risk Score + Recommended Action
```

A `fast_mode=true` flag bypasses the transformer entirely for latency-sensitive workloads.

---

## Rationale

### Regex advantages

- **Zero latency** — pattern matching completes in microseconds.
- **100 % precision** for structured formats (CNIC regex `\b\d{5}-\d{7}-\d\b` never produces
  false positives on well-formed input).
- **Works offline** — no network calls, no GPU required.
- **Deterministic** — identical input always produces identical output (auditable, testable).
- **Pakistan-specific** — custom patterns for CNIC, IBAN (`PK\d{2}[A-Z]{4}\d{16}`), and
  local phone formats that off-the-shelf models do not know.

### Transformer advantages

- **Catches unstructured PII** — person names, organisation names, and locations mentioned
  naturally in prose (e.g. "Please send the report to Ahmed Khan at Finance").
- **Handles variations and misspellings** — the model generalises beyond hardcoded patterns.
- **Contextual understanding** — "Apple" is an organisation in one sentence and a fruit in another;
  NER resolves ambiguity from context.

### Why hybrid wins

| Criterion | Regex only | NER only | Hybrid |
|---|---|---|---|
| Structured PII (CNIC, email) | ✅ Perfect | ⚠️ Misses formats | ✅ Regex handles |
| Unstructured PII (names) | ❌ Blind | ✅ Good | ✅ NER handles |
| Latency (p50) | < 1 ms | ~200 ms | < 1 ms (fast) / ~200 ms (full) |
| Pakistan-specific formats | ✅ Custom | ❌ Unknown | ✅ Custom |
| Offline / air-gapped | ✅ | ❌ (needs model) | ✅ (model pre-downloaded) |
| False-positive rate | Very low | Medium | Low (dedup + confidence threshold) |

The hybrid pipeline uses `fast_mode=true` to skip the transformer when speed is critical,
and enables full NER for standard scans. A confidence threshold (`NER_MIN_CONFIDENCE=0.85`)
filters low-confidence NER results to keep false-positive rates acceptable.

---

## Consequences

### Positive

- Higher recall than either approach alone.
- Regex catches CNIC, credit cards, and API keys with zero latency.
- NER catches person names and organisation names that regex cannot.
- `fast_mode` flag lets callers trade recall for speed when needed.

### Negative / Mitigations

| Consequence | Mitigation |
|---|---|
| Backend requires 1–2 GB RAM for the NER model in memory | Set K8s memory limit to 1 Gi (pod spec); use CPU-optimised quantised model in `requirements_cpu.txt` |
| First request after cold start is slow (~30 s — model load) | Model pre-downloaded in Dockerfile (`RUN python -c "from transformers import pipeline…"`); K8s `readinessProbe` has `initialDelaySeconds: 30` so no traffic reaches the pod until model is warm |
| NER model may drift or be deprecated on HuggingFace Hub | Model name is configurable via `NER_MODEL_NAME` env var; DVC tracks model version |
| Transformer adds ~200 ms to each full scan | Acceptable for dashboard use-case; `fast_mode=true` available for high-throughput callers |

---

## Alternatives Considered

### 1. Pure regex

**Rejected.** Misses person names, organisation names, and free-text PII. A bank employee's
name typed into a chat message would pass through undetected.

### 2. Pure NER (transformer only)

**Rejected.** `dslim/bert-base-NER` was not trained on Pakistani CNIC or IBAN formats and
produces inconsistent results for structured numeric identifiers. Cold-start latency (~30 s)
makes it unsuitable as the sole detection layer.

### 3. External API (AWS Comprehend / Google DLP)

**Rejected.** Adds per-request cost, network latency (~100–400 ms), and routes sensitive
customer data to a third-party cloud service — violating the data-residency requirements
for Pakistani enterprise customers. Also prevents air-gapped deployments.

### 4. spaCy NER

**Rejected.** spaCy's pre-trained English models have lower recall for person names in
South-Asian name contexts compared to `dslim/bert-base-NER`. The HuggingFace ecosystem
also enables straightforward model swapping via the `NER_MODEL_NAME` env var.

---

## References

- [`backend/app/services/scanner.py`](../../backend/app/services/scanner.py) — hybrid scanner implementation
- [`backend/app/services/ner_model.py`](../../backend/app/services/ner_model.py) — NER pipeline (`run_ner`)
- [`backend/app/models/schemas.py`](../../backend/app/models/schemas.py) — `EntityType` enum (CNIC, EMAIL, …)
- [dslim/bert-base-NER on HuggingFace Hub](https://huggingface.co/dslim/bert-base-NER)
