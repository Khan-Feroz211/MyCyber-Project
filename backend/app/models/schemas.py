from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field


# ---------------------------------------------------------------------------
# Existing enumerations and schemas (kept exactly as defined)
# ---------------------------------------------------------------------------


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    SAFE = "SAFE"


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
    CUSTOM = "CUSTOM"


class DetectedEntity(BaseModel):
    entity_type: EntityType
    value: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    start_pos: Optional[int] = None
    end_pos: Optional[int] = None
    context: Optional[str] = None


class ScanTextRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=1_000_000)
    scan_id: Optional[str] = None


class ScanFileRequest(BaseModel):
    filename: str
    content_base64: str
    scan_id: Optional[str] = None


class ScanNetworkRequest(BaseModel):
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    payload: str = Field(..., min_length=1)
    scan_id: Optional[str] = None


class ScanResponse(BaseModel):
    scan_id: str
    severity: SeverityLevel
    risk_score: float = Field(..., ge=0.0, le=100.0)
    entities: list[DetectedEntity] = Field(default_factory=list)
    total_entities: int = 0
    recommended_action: str
    summary: str
    scan_duration_ms: float


class HealthResponse(BaseModel):
    status: str
    version: str
    model_loaded: bool
    database_connected: bool
    uptime_seconds: float


# ---------------------------------------------------------------------------
# Authentication schemas
# ---------------------------------------------------------------------------


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=100)
    full_name: str = Field(default="")


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    full_name: Optional[str]
    is_active: bool
    plan: str
    tenant_id: str
    scan_count_month: int
    created_at: datetime


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut


class TokenData(BaseModel):
    user_id: int
    email: str
    tenant_id: str


# ---------------------------------------------------------------------------
# Scan history schemas
# ---------------------------------------------------------------------------


class ScanHistoryItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    scan_id: str
    scan_type: str
    severity: str
    risk_score: float
    total_entities: int
    recommended_action: str
    summary: str
    input_preview: Optional[str]
    filename: Optional[str]
    source_ip: Optional[str]
    scan_duration_ms: float
    created_at: datetime


class ScanHistoryResponse(BaseModel):
    items: list[ScanHistoryItem]
    total: int
    page: int
    page_size: int
    has_more: bool


# ---------------------------------------------------------------------------
# Alert schemas
# ---------------------------------------------------------------------------


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    alert_id: str
    severity: str
    title: str
    description: str
    is_acknowledged: bool
    created_at: datetime
    scan_id: str


class AlertsResponse(BaseModel):
    alerts: list[AlertOut]
    total: int
    unacknowledged: int


class AcknowledgeRequest(BaseModel):
    alert_id: str


# ---------------------------------------------------------------------------
# Plan / billing schemas
# ---------------------------------------------------------------------------


class PlanLimitError(BaseModel):
    error: str = "plan_limit_exceeded"
    message: str
    current_plan: str
    limit: int
    upgrade_url: str = "/api/v1/billing/upgrade"


PLAN_LIMITS: dict[str, int] = {
    "free": 100,
    "pro": 10_000,
    "enterprise": 999_999,
}
