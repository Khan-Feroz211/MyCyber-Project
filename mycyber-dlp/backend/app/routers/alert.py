from fastapi import APIRouter

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])


@router.get("")
async def list_alerts():
    """Stub: alert listing — to be implemented."""
    return {"alerts": [], "total": 0}
