"""LLM DLP router."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.database import get_db
from ..db.models import LLMInteraction, User
from ..dependencies import get_current_user
from ..mlops.logger import get_logger
from ..services.llm_dlp_service import run_llm_dlp_pipeline

router = APIRouter(prefix="/llm-dlp", tags=["llm-dlp"])
logger = get_logger(__name__)


class ChatRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=50000)
    provider: str = Field(default="openai")
    model: Optional[str] = None
    skip_redaction: bool = Field(default=False)


class ChatResponse(BaseModel):
    interaction_id: str
    status: str
    reason: Optional[str] = None
    pre_entities: list[dict]
    redacted_prompt: Optional[str]
    llm_response: Optional[str]
    post_entities: list[dict]
    deactivated_keys: list[dict]


@router.post("/chat", response_model=ChatResponse, status_code=status.HTTP_200_OK)
async def llm_dlp_chat(
    req: ChatRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ChatResponse:
    """Send a prompt through the DLP pipeline: pre-scan -> redact -> LLM -> post-scan."""
    result = await run_llm_dlp_pipeline(
        db=db,
        user=current_user,
        prompt=req.prompt,
        provider=req.provider,
        model=req.model,
        skip_redaction=req.skip_redaction,
    )
    return ChatResponse(**result)


@router.get("/history", status_code=status.HTTP_200_OK)
async def list_llm_history(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    status_filter: Optional[str] = Query(default=None),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Paginated list of LLM DLP interactions for the tenant."""
    base = select(LLMInteraction).where(LLMInteraction.tenant_id == current_user.tenant_id)
    if status_filter:
        base = base.where(LLMInteraction.status == status_filter)

    count_result = await db.execute(select(func.count()).select_from(base.subquery()))
    total = count_result.scalar_one()

    offset = (page - 1) * page_size
    rows_result = await db.execute(
        base.order_by(desc(LLMInteraction.created_at)).offset(offset).limit(page_size)
    )
    items = rows_result.scalars().all()

    return {
        "items": [
            {
                "interaction_id": i.interaction_id,
                "status": i.status,
                "original_preview": i.original_prompt[:120] + "..." if len(i.original_prompt) > 120 else i.original_prompt,
                "llm_provider": i.llm_provider,
                "model_used": i.model_used,
                "auto_deactivated": i.auto_deactivated,
                "created_at": i.created_at.isoformat() if i.created_at else None,
            }
            for i in items
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
        "has_more": (offset + len(items)) < total,
    }


@router.get("/history/{interaction_id}", status_code=status.HTTP_200_OK)
async def get_llm_interaction_detail(
    interaction_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Full detail of a single LLM interaction."""
    result = await db.execute(
        select(LLMInteraction).where(
            LLMInteraction.interaction_id == interaction_id,
            LLMInteraction.tenant_id == current_user.tenant_id,
        )
    )
    i = result.scalar_one_or_none()
    if not i:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Interaction not found")

    import json
    return {
        "interaction_id": i.interaction_id,
        "status": i.status,
        "original_prompt": i.original_prompt,
        "redacted_prompt": i.redacted_prompt,
        "llm_response": i.llm_response,
        "pre_entities": json.loads(i.pre_entities_json or "[]"),
        "post_entities": json.loads(i.post_entities_json or "[]"),
        "exposed_keys": json.loads(i.exposed_keys_json or "[]"),
        "auto_deactivated": i.auto_deactivated,
        "llm_provider": i.llm_provider,
        "model_used": i.model_used,
        "created_at": i.created_at.isoformat() if i.created_at else None,
    }


@router.get("/stats", status_code=status.HTTP_200_OK)
async def get_llm_stats(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Dashboard stats for LLM DLP usage."""
    base = select(LLMInteraction).where(LLMInteraction.tenant_id == current_user.tenant_id)

    total_result = await db.execute(select(func.count()).select_from(base.subquery()))
    total = total_result.scalar_one()

    blocked_result = await db.execute(
        select(func.count()).select_from(
            base.where(LLMInteraction.status == "blocked").subquery()
        )
    )
    blocked = blocked_result.scalar_one()

    redacted_result = await db.execute(
        select(func.count()).select_from(
            base.where(LLMInteraction.status == "redacted").subquery()
        )
    )
    redacted = redacted_result.scalar_one()

    violation_result = await db.execute(
        select(func.count()).select_from(
            base.where(LLMInteraction.status == "violation").subquery()
        )
    )
    violation = violation_result.scalar_one()

    leaked_result = await db.execute(
        select(func.count()).select_from(
            base.where(LLMInteraction.auto_deactivated == True).subquery()
        )
    )
    leaked = leaked_result.scalar_one()

    return {
        "total_interactions": total,
        "blocked": blocked,
        "redacted": redacted,
        "violations": violation,
        "leaked_keys_detected": leaked,
    }
