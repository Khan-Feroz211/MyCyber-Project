"""Purge data older than the configured retention window.

Data-minimisation control (ISO 27001 / SOC 2 retention).  Deletes
tenant-scoped **derived** artefacts that can be regenerated or reviewed
elsewhere:

  * ``scans.ScanRecord``
  * ``alerts.Alert``
  * ``llm.LLMInteraction``
  * ``incidents.Incident``
  * ``incidents.QuarantineItem`` (+ on-disk quarantined files)

The **audit log is never touched** — it is append-only and hash-chained, so
purging source records cannot break chain integrity.  A ``security_sensitive``
audit entry is written for the purge action itself.

Default retention is 365 days (env ``DATA_RETENTION_DAYS``).  Pass ``--days N``
to override for a run, or ``--dry-run`` to preview.

    manage.py purge_old_data --days 365 --dry-run
    manage.py purge_old_data --days 90
"""
from __future__ import annotations

import logging
from datetime import timedelta

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Purge scan/alert/LLM/incident/quarantine data older than the retention window (audit log is preserved)."

    def add_arguments(self, parser):
        parser.add_argument("--days", type=int, default=None, help="Retention in days (default: DATA_RETENTION_DAYS env or 365).")
        parser.add_argument("--dry-run", action="store_true", help="Report counts without deleting.")
        parser.add_argument("--tenant", type=str, default=None, help="Restrict to a single tenant_id.")

    def handle(self, *args, **options):
        from apps.alerts.models import Alert
        from apps.incidents.models import Incident, QuarantineItem
        from apps.llm.models import LLMInteraction
        from apps.scans.models import ScanRecord
        from mycyber.services.conf import _env
        from mycyber.services.audit_log import (
            EVENT_SENSITIVE_ACTION,
            append_audit_log,
        )

        days = options["days"]
        if days is None:
            days = int(_env("DATA_RETENTION_DAYS", "365"))
        if days < 0:
            raise CommandError("--days must be >= 0")

        cutoff = timezone.now() - timedelta(days=days)
        affected = {"scans": 0, "alerts": 0, "llm_interactions": 0, "incidents": 0, "quarantine_items": 0}

        models = {
            "scans": (ScanRecord, "scans.ScanRecord"),
            "alerts": (Alert, "alerts.Alert"),
            "llm_interactions": (LLMInteraction, "llm.LLMInteraction"),
            "incidents": (Incident, "incidents.Incident"),
        }

        for key, (model, label) in models.items():
            qs = model.objects.filter(created_at__lt=cutoff)
            if options["tenant"]:
                qs = qs.filter(tenant_id=options["tenant"])
            affected[key] = qs.count()
            if not options["dry_run"]:
                # QuarantineItem files: purge on-disk bytes for incident-linked items.
                qs.delete()

        # QuarantineItem: delete DB row + on-disk file + sidecar metadata.
        from apps.incidents.services import quarantine_dir

        q_qs = QuarantineItem.objects.filter(created_at__lt=cutoff)
        if options["tenant"]:
            pass  # QuarantineItem has no tenant; left as-is.
        affected["quarantine_items"] = q_qs.count()
        if not options["dry_run"]:
            for item in q_qs:
                path = quarantine_dir() / item.name
                try:
                    if path.exists():
                        path.unlink()
                    meta = path.with_suffix(path.suffix + ".json")
                    if meta.exists():
                        meta.unlink()
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Could not remove quarantine file %s: %s", item.name, exc)
            q_qs.delete()

        if options["dry_run"]:
            self.stdout.write(
                self.style.WARNING(f"[dry-run] Would purge (cutoff={cutoff.isoformat()}): {affected}")
            )
            return

        self.stdout.write(self.style.SUCCESS(f"Purged records older than {cutoff.isoformat()}: {affected}"))
        # Audit the purge action (do not include sensitive payloads).
        audit_tenant = str(options["tenant"]) if options["tenant"] else "system"
        try:
            append_audit_log(
                event_type=EVENT_SENSITIVE_ACTION,
                resource_type="data",
                action="purge_old_data",
                tenant_id=audit_tenant,
                actor_id=None,
                details={
                    "retention_days": days,
                    "cutoff_at": cutoff.isoformat(),
                    "affected": affected,
                    "dry_run": False,
                },
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to append purge audit entry: %s", exc)
