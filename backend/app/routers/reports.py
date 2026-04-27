from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import PlainTextResponse, StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.database import get_db
from ..db.models import ScanRecord, User
from ..dependencies import get_current_user
from ..mlops.logger import get_logger
from ..services.scan_store import get_scan_history

router = APIRouter(prefix="/reports", tags=["reports"])
logger = get_logger(__name__)


@router.get("/export/csv")
async def export_csv(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    severity: str | None = Query(default=None),
    scan_type: str | None = Query(default=None),
    limit: int = Query(default=500, ge=1, le=5000),
) -> StreamingResponse:
    """Export scan history as a CSV file."""
    history = await get_scan_history(
        db=db,
        user=current_user,
        page=1,
        page_size=limit,
        severity=severity,
        scan_type=scan_type,
    )

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "scan_id", "scan_type", "severity", "risk_score",
        "total_entities", "recommended_action", "summary",
        "filename", "source_ip", "created_at",
    ])

    for row in history.items:
        writer.writerow([
            row.scan_id,
            row.scan_type,
            row.severity,
            row.risk_score,
            row.total_entities,
            row.recommended_action,
            row.summary,
            row.filename or "",
            row.source_ip or "",
            row.created_at.isoformat() if row.created_at else "",
        ])

    output.seek(0)
    filename = f"mycyber_scans_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"

    return StreamingResponse(
        io.BytesIO(output.getvalue().encode("utf-8-sig")),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/export/html")
async def export_html(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    severity: str | None = Query(default=None),
    scan_type: str | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=2000),
) -> PlainTextResponse:
    """Export scan history as a printable HTML report (save as PDF from browser)."""
    history = await get_scan_history(
        db=db,
        user=current_user,
        page=1,
        page_size=limit,
        severity=severity,
        scan_type=scan_type,
    )

    rows_html = ""
    for row in history.items:
        color = {
            "CRITICAL": "#ef4444",
            "HIGH": "#f97316",
            "MEDIUM": "#eab308",
            "LOW": "#38bdf8",
            "SAFE": "#34d399",
        }.get(row.severity, "#94a3b8")

        rows_html += (
            f"<tr>"
            f"<td>{row.scan_id}</td>"
            f"<td>{row.scan_type}</td>"
            f'<td style="color:{color};font-weight:bold">{row.severity}</td>'
            f"<td>{row.risk_score}</td>"
            f"<td>{row.total_entities}</td>"
            f"<td>{row.recommended_action}</td>"
            f"<td>{row.summary[:120]}</td>"
            f"<td>{row.created_at.strftime('%Y-%m-%d %H:%M') if row.created_at else '-'}</td>"
            f"</tr>"
        )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>MyCyber DLP Report — {current_user.email}</title>
<style>
  body {{ font-family: Arial, sans-serif; margin: 40px; color: #1e293b; }}
  h1 {{ font-size: 24px; margin-bottom: 8px; }}
  .meta {{ color: #64748b; font-size: 14px; margin-bottom: 24px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{ border: 1px solid #cbd5e1; padding: 8px 10px; text-align: left; }}
  th {{ background: #0f172a; color: #f8fafc; }}
  tr:nth-child(even) {{ background: #f8fafc; }}
  @media print {{
    body {{ margin: 20px; }}
    .no-print {{ display: none; }}
  }}
</style>
</head>
<body>
  <h1>MyCyber DLP — Scan Report</h1>
  <div class="meta">
    Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}<br>
    User: {current_user.email}<br>
    Records: {len(history.items)}
  </div>
  <div class="no-print" style="margin-bottom:16px">
    <button onclick="window.print()">Print / Save as PDF</button>
  </div>
  <table>
    <thead>
      <tr>
        <th>Scan ID</th><th>Type</th><th>Severity</th><th>Risk</th>
        <th>Entities</th><th>Action</th><th>Summary</th><th>Date</th>
      </tr>
    </thead>
    <tbody>
      {rows_html}
    </tbody>
  </table>
</body>
</html>"""

    return PlainTextResponse(
        content=html,
        media_type="text/html; charset=utf-8",
    )


@router.get("/export/json")
async def export_json(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    severity: str | None = Query(default=None),
    scan_type: str | None = Query(default=None),
    limit: int = Query(default=500, ge=1, le=5000),
) -> StreamingResponse:
    """Export scan history as a JSON file."""
    history = await get_scan_history(
        db=db,
        user=current_user,
        page=1,
        page_size=limit,
        severity=severity,
        scan_type=scan_type,
    )

    data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "user_email": current_user.email,
        "total_records": len(history.items),
        "scans": [
            {
                "scan_id": row.scan_id,
                "scan_type": row.scan_type,
                "severity": row.severity,
                "risk_score": row.risk_score,
                "total_entities": row.total_entities,
                "recommended_action": row.recommended_action,
                "summary": row.summary,
                "filename": row.filename,
                "source_ip": row.source_ip,
                "created_at": row.created_at.isoformat() if row.created_at else None,
                "entities": row.entities if hasattr(row, "entities") else [],
            }
            for row in history.items
        ],
    }

    json_str = json.dumps(data, indent=2, default=str)
    filename = f"mycyber_scans_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"

    return StreamingResponse(
        io.BytesIO(json_str.encode("utf-8")),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
