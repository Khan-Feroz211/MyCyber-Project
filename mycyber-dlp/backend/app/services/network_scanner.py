from app.models.schemas import DetectedEntity, ScanNetworkRequest
from app.services import pii_scanner


async def scan_network(req: ScanNetworkRequest) -> list[DetectedEntity]:
    """
    Scans a network payload for PII/sensitive data.
    Combines payload and destination for scanning.
    """
    combined = req.payload
    if req.destination:
        combined = f"{req.destination}\n{req.payload}"
    return await pii_scanner.scan_text(
        text=combined,
        context="network",
        use_transformer=True,
    )
