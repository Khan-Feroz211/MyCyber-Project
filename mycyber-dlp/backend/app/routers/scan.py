from fastapi import APIRouter, Query

from app.config import get_settings
from app.models.schemas import (
    DetectedEntity,
    EntityType,
    ScanFileRequest,
    ScanNetworkRequest,
    ScanTextRequest,
    ScanTextResponse,
    SeverityLevel,
)
from app.services import file_scanner, network_scanner, pii_scanner
from app.services.leakage_scorer import calculate_risk_score, determine_severity

router = APIRouter(prefix="/api/v1/scan", tags=["scan"])
settings = get_settings()


@router.post("/text", response_model=ScanTextResponse)
async def scan_text_endpoint(
    req: ScanTextRequest,
    fast_mode: bool = Query(default=False, description="Skip transformer, regex only"),
):
    use_transformer = settings.use_transformer and not fast_mode
    entities = await pii_scanner.scan_text(
        text=req.text,
        context=req.context,
        use_transformer=use_transformer,
    )
    risk_score = calculate_risk_score(entities)
    severity = determine_severity(risk_score)
    return ScanTextResponse(
        text=req.text,
        total_entities=len(entities),
        entities=entities,
        risk_score=risk_score,
        severity=severity,
        context=req.context,
    )


@router.post("/file")
async def scan_file_endpoint(req: ScanFileRequest):
    entities = await file_scanner.scan_file(req)
    risk_score = calculate_risk_score(entities)
    severity = determine_severity(risk_score)
    return {
        "filename": req.filename,
        "total_entities": len(entities),
        "entities": [e.model_dump() for e in entities],
        "risk_score": risk_score,
        "severity": severity.value,
    }


@router.post("/network")
async def scan_network_endpoint(req: ScanNetworkRequest):
    entities = await network_scanner.scan_network(req)
    risk_score = calculate_risk_score(entities)
    severity = determine_severity(risk_score)
    return {
        "destination": req.destination,
        "total_entities": len(entities),
        "entities": [e.model_dump() for e in entities],
        "risk_score": risk_score,
        "severity": severity.value,
    }


@router.get("/models/info")
async def model_info():
    """
    Returns info about loaded ML models.
    Used by health dashboard and monitoring.
    """
    return {
        "ner_model": settings.ner_model_name,
        "use_transformer": settings.use_transformer,
        "regex_patterns": 9,
        "entity_types_supported": [e.value for e in EntityType],
    }
