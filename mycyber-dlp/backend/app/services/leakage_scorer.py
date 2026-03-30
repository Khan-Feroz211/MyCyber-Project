from app.models.schemas import DetectedEntity, EntityType, SeverityLevel

# Risk weight per entity type
ENTITY_RISK_WEIGHTS: dict[EntityType, float] = {
    EntityType.CNIC: 10.0,
    EntityType.CREDIT_CARD: 10.0,
    EntityType.IBAN: 9.0,
    EntityType.PASSWORD: 9.0,
    EntityType.API_KEY: 8.0,
    EntityType.EMAIL: 5.0,
    EntityType.PHONE: 5.0,
    EntityType.URL_WITH_TOKEN: 7.0,
    EntityType.IP_ADDRESS: 3.0,
    EntityType.CUSTOM: 4.0,
}

# Severity mapping per entity type (used by NER converter too)
ENTITY_SEVERITY_MAP: dict[EntityType, SeverityLevel] = {
    EntityType.CNIC: SeverityLevel.CRITICAL,
    EntityType.CREDIT_CARD: SeverityLevel.CRITICAL,
    EntityType.IBAN: SeverityLevel.CRITICAL,
    EntityType.PASSWORD: SeverityLevel.CRITICAL,
    EntityType.API_KEY: SeverityLevel.CRITICAL,
    EntityType.EMAIL: SeverityLevel.HIGH,
    EntityType.PHONE: SeverityLevel.HIGH,
    EntityType.URL_WITH_TOKEN: SeverityLevel.HIGH,
    EntityType.IP_ADDRESS: SeverityLevel.MEDIUM,
    EntityType.CUSTOM: SeverityLevel.MEDIUM,
}


def calculate_risk_score(entities: list[DetectedEntity]) -> float:
    """
    Calculates a cumulative risk score based on detected entities.
    Each entity contributes its weight * confidence to the total.
    Score is capped at 100.0.
    """
    if not entities:
        return 0.0
    score = sum(
        ENTITY_RISK_WEIGHTS.get(e.entity_type, 1.0) * e.confidence
        for e in entities
    )
    return min(round(score, 2), 100.0)


def determine_severity(risk_score: float) -> SeverityLevel:
    """
    Maps a numeric risk score to a SeverityLevel.
    """
    if risk_score == 0.0:
        return SeverityLevel.SAFE
    elif risk_score < 3.0:
        return SeverityLevel.LOW
    elif risk_score < 6.0:
        return SeverityLevel.MEDIUM
    elif risk_score < 9.0:
        return SeverityLevel.HIGH
    else:
        return SeverityLevel.CRITICAL
