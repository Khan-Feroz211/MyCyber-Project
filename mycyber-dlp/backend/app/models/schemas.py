from enum import Enum
from typing import Optional
from pydantic import BaseModel


class EntityType(str, Enum):
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    CNIC = "CNIC"
    CREDIT_CARD = "CREDIT_CARD"
    IP_ADDRESS = "IP_ADDRESS"
    API_KEY = "API_KEY"
    PASSWORD = "PASSWORD"
    IBAN = "IBAN"
    URL_WITH_TOKEN = "URL_WITH_TOKEN"
    CUSTOM = "CUSTOM"


class SeverityLevel(str, Enum):
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DetectedEntity(BaseModel):
    entity_type: EntityType
    value: str
    redacted_value: str
    confidence: float
    severity: SeverityLevel
    position_start: int
    position_end: int


class ScanTextRequest(BaseModel):
    text: str
    context: str = "general"


class ScanTextResponse(BaseModel):
    text: str
    total_entities: int
    entities: list[DetectedEntity]
    risk_score: float
    severity: SeverityLevel
    context: str


class ScanFileRequest(BaseModel):
    filename: str
    content: str
    context: str = "general"


class ScanNetworkRequest(BaseModel):
    payload: str
    destination: str = ""
    context: str = "network"
