import asyncio
from app.models.schemas import DetectedEntity, ScanFileRequest, SeverityLevel
from app.services import pii_scanner


async def scan_file(req: ScanFileRequest) -> list[DetectedEntity]:
    """
    Scans file content for PII using the hybrid scanner.
    Detects context from the filename extension.
    """
    context = req.context
    name_lower = req.filename.lower()
    if name_lower.endswith((".py", ".js", ".ts", ".go", ".java", ".rb", ".sh")):
        context = "code"
    elif name_lower.endswith((".eml", ".msg")):
        context = "email"

    return await pii_scanner.scan_text(
        text=req.content,
        context=context,
        use_transformer=True,
    )
