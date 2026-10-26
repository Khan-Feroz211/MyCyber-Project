"""Incidents/reports/quarantine service (Django port of the FastAPI report +
quarantine routers plus ``services/quarantine.py``).
"""
from __future__ import annotations

import csv
import html as html_lib
import io
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from apps.incidents.models import Incident, QuarantineItem

logger = logging.getLogger(__name__)


def quarantine_dir() -> Path:
    from django.conf import settings

    base = getattr(settings, "QUARANTINE_DIR", None)
    if not base:
        base = os.getenv("QUARANTINE_DIR", str(Path(getattr(settings, "MEDIA_ROOT", "media")) / "quarantine"))
    path = Path(base)
    path.mkdir(parents=True, exist_ok=True)
    return path


_QUARANTINE_COLORS = {
    "CRITICAL": "#ef4444",
    "HIGH": "#f97316",
    "MEDIUM": "#eab308",
    "LOW": "#38bdf8",
    "SAFE": "#34d399",
}


# ---------------------------------------------------------------------------
# Quarantine (filesystem-backed)
# ---------------------------------------------------------------------------


def _safe_path(name: str) -> Path:
    p = Path(name)
    if p.name != name:  # reject traversal
        raise ValueError("Invalid filename")
    return quarantine_dir() / name


def quarantine_bytes(filename: str, data: bytes, meta: dict | None = None) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_name = f"{ts}-{Path(filename).name}"
    dest = _safe_path(safe_name)
    with open(dest, "wb") as fh:
        fh.write(data)
    meta = dict(meta or {})
    meta_path = dest.with_suffix(dest.suffix + ".json")
    with open(meta_path, "w", encoding="utf-8") as mh:
        json.dump({"created_at": ts, **meta}, mh, ensure_ascii=False, indent=2)
    QuarantineItem.objects.create(name=safe_name, size=len(data), meta_json=json.dumps(meta))
    logger.info("Quarantined file %s to %s", filename, dest)
    return str(dest)


def list_quarantine() -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    qdir = quarantine_dir()
    for f in sorted(qdir.iterdir()):
        if f.is_file() and not f.suffix == ".json":
            meta_path = f.with_suffix(f.suffix + ".json")
            meta: dict = {}
            if meta_path.exists():
                try:
                    with open(meta_path, "r", encoding="utf-8") as mh:
                        meta = json.load(mh)
                except Exception:  # noqa: BLE001
                    meta = {}
            items.append({"name": f.name, "size": f.stat().st_size, "meta": meta})
    return items


def get_quarantine_item(name: str) -> dict[str, Any]:
    p = _safe_path(name)
    if not p.exists():
        from rest_framework.exceptions import NotFound

        raise NotFound("Item not found")
    meta_path = p.with_suffix(p.suffix + ".json")
    meta: dict = {}
    if meta_path.exists():
        with open(meta_path, "r", encoding="utf-8") as mh:
            meta = json.load(mh)
    return {"name": p.name, "size": p.stat().st_size, "meta": meta}


def release_quarantine_item(name: str) -> dict[str, Any]:
    p = _safe_path(name)
    if not p.exists():
        from rest_framework.exceptions import NotFound

        raise NotFound("Item not found")
    released_dir = p.parent / "released"
    released_dir.mkdir(exist_ok=True)
    dest = released_dir / p.name
    p.rename(dest)
    meta = p.with_suffix(p.suffix + ".json")
    if meta.exists():
        meta.rename(dest.with_suffix(dest.suffix + ".json"))
    return {"released_to": str(dest)}


def delete_quarantine_item(name: str) -> dict[str, Any]:
    p = _safe_path(name)
    if not p.exists():
        from rest_framework.exceptions import NotFound

        raise NotFound("Item not found")
    meta = p.with_suffix(p.suffix + ".json")
    try:
        p.unlink()
        if meta.exists():
            meta.unlink()
    except Exception as exc:  # noqa: BLE001
        from rest_framework.exceptions import APIException

        raise APIException(str(exc))
    return {"deleted": name}


# ---------------------------------------------------------------------------
# Incident records
# ---------------------------------------------------------------------------


def create_incident(
    user,
    severity: str,
    title: str,
    description: str,
    details: dict | None = None,
) -> Incident:
    from mycyber.services.audit_log import EVENT_SENSITIVE_ACTION, append_audit_log

    inc = Incident.objects.create(
        user=user,
        tenant_id=str(user.tenant_id),
        severity=severity,
        title=title,
        description=description,
        status="open",
        details_json=json.dumps(details or {}),
    )
    try:
        append_audit_log(
            event_type=EVENT_SENSITIVE_ACTION,
            resource_type="incident",
            action="create",
            tenant_id=str(user.tenant_id),
            actor=user,
            resource_id=str(inc.incident_id),
            severity=severity,
            details=details or {},
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("Failed to append incident audit: %s", exc)
    return inc


# ---------------------------------------------------------------------------
# Reports (CSV / HTML / JSON export of scan history)
# ---------------------------------------------------------------------------


def _history_rows(user, severity: str | None = None, scan_type: str | None = None, limit: int = 500):
    from apps.scans.services import get_scan_history

    return get_scan_history(
        user=user,
        page=1,
        page_size=limit,
        severity_filter=severity,
        scan_type_filter=scan_type,
    )["items"]


def export_csv(user, severity: str | None = None, scan_type: str | None = None, limit: int = 500) -> bytes:
    rows = _history_rows(user, severity=severity, scan_type=scan_type, limit=limit)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "scan_id", "scan_type", "severity", "risk_score",
        "total_entities", "recommended_action", "summary",
        "filename", "source_ip", "created_at",
    ])
    for row in rows:
        writer.writerow([
            row["scan_id"], row["scan_type"], row["severity"], row["risk_score"],
            row["total_entities"], row["recommended_action"], row["summary"],
            row["filename"] or "", row["source_ip"] or "", row["created_at"] or "",
        ])
    return output.getvalue().encode("utf-8-sig")


def export_html(user, severity: str | None = None, scan_type: str | None = None, limit: int = 200) -> str:
    rows = _history_rows(user, severity=severity, scan_type=scan_type, limit=limit)
    e = html_lib.escape
    rows_html = ""
    for row in rows:
        color = _QUARANTINE_COLORS.get(row["severity"], "#94a3b8")
        sev = e(row["severity"] or "")
        rows_html += (
            f"<tr>"
            f"<td>{e(row['scan_id'])}</td>"
            f"<td>{e(row['scan_type'])}</td>"
            f'<td style="color:{color};font-weight:bold">{sev}</td>'
            f"<td>{e(str(row['risk_score']))}</td>"
            f"<td>{e(str(row['total_entities']))}</td>"
            f"<td>{e(row['recommended_action'] or '')}</td>"
            f"<td>{e((row['summary'] or '')[:120])}</td>"
            f"<td>{e(row['created_at'] or '-')}</td>"
            f"</tr>"
        )
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>MyCyber DLP Report — {e(user.email)}</title>
<style>
  body {{ font-family: Arial, sans-serif; margin: 40px; color: #1e293b; }}
  h1 {{ font-size: 24px; margin-bottom: 8px; }}
  .meta {{ color: #64748b; font-size: 14px; margin-bottom: 24px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{ border: 1px solid #cbd5e1; padding: 8px 10px; text-align: left; }}
  th {{ background: #0f172a; color: #f8fafc; }}
  tr:nth-child(even) {{ background: #f8fafc; }}
  @media print {{ body {{ margin: 20px; }} .no-print {{ display: none; }} }}
</style>
</head>
<body>
  <h1>MyCyber DLP — Scan Report</h1>
  <div class="meta">
    Generated: {now_str}<br>
    User: {e(user.email)}<br>
    Records: {len(rows)}
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


def export_json(user, severity: str | None = None, scan_type: str | None = None, limit: int = 500) -> bytes:
    rows = _history_rows(user, severity=severity, scan_type=scan_type, limit=limit)
    data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "user_email": user.email,
        "total_records": len(rows),
        "scans": rows,
    }
    return json.dumps(data, indent=2, default=str).encode("utf-8")
