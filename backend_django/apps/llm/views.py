"""LLM-DLP HTTP views (DRF port of ``backend/app/routers/llm_dlp.py``).

Mounted under ``/api/v1/llm-dlp/``.
"""
from __future__ import annotations

import json as _json

from rest_framework import permissions, status, views
from rest_framework.exceptions import NotFound
from rest_framework.response import Response

from apps.llm.models import LLMInteraction


class LlmChatAPI(views.APIView):
    """POST /llm-dlp/chat — run the DLP pipeline over a prompt."""

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        prompt = request.data.get("prompt", "")
        if not prompt:
            return Response({"detail": "Field 'prompt' is required."}, status=status.HTTP_400_BAD_REQUEST)
        from apps.llm.services import run_llm_dlp_pipeline

        result = run_llm_dlp_pipeline(
            user=request.user,
            prompt=prompt,
            provider=request.data.get("provider", "openai"),
            model=request.data.get("model"),
            skip_redaction=bool(request.data.get("skip_redaction", False)),
        )
        return Response(result, status=status.HTTP_200_OK)


class LlmHistoryAPI(views.APIView):
    """GET /llm-dlp/history — paginated interactions."""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        page = int(request.query_params.get("page", "1"))
        page_size = min(int(request.query_params.get("page_size", "20")), 100)
        status_filter = request.query_params.get("status")
        qs = LLMInteraction.objects.filter(user=request.user).order_by("-created_at")
        if status_filter:
            qs = qs.filter(status=status_filter)
        total = qs.count()
        offset = (page - 1) * page_size
        rows = list(qs[offset : offset + page_size])
        items = [
            {
                "interaction_id": str(i.interaction_id),
                "status": i.status,
                "original_preview": (i.original_prompt[:120] + "...") if i.original_prompt and len(i.original_prompt) > 120 else i.original_prompt,
                "llm_provider": i.llm_provider,
                "model_used": i.model_used,
                "auto_deactivated": i.auto_deactivated,
                "created_at": i.created_at.isoformat() if i.created_at else None,
            }
            for i in rows
        ]
        return Response(
            {
                "items": items,
                "total": total,
                "page": page,
                "page_size": page_size,
                "has_more": (offset + len(items)) < total,
            }
        )


class LlmInteractionDetailAPI(views.APIView):
    """GET /llm-dlp/history/{interaction_id}."""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, interaction_id):
        try:
            i = LLMInteraction.objects.get(interaction_id=interaction_id, user=request.user)
        except (LLMInteraction.DoesNotExist, ValueError):
            raise NotFound("Interaction not found")
        try:
            pre_entities = _json.loads(i.pre_entities_json or "[]")
            post_entities = _json.loads(i.post_entities_json or "[]")
            exposed = _json.loads(i.exposed_keys_json or "[]")
        except ValueError:
            pre_entities = post_entities = exposed = []
        return Response(
            {
                "interaction_id": str(i.interaction_id),
                "status": i.status,
                "original_prompt": i.original_prompt,
                "redacted_prompt": i.redacted_prompt,
                "llm_response": i.llm_response,
                "pre_entities": pre_entities,
                "post_entities": post_entities,
                "exposed_keys": exposed,
                "auto_deactivated": i.auto_deactivated,
                "llm_provider": i.llm_provider,
                "model_used": i.model_used,
                "created_at": i.created_at.isoformat() if i.created_at else None,
            }
        )


class LlmStatsAPI(views.APIView):
    """GET /llm-dlp/stats — dashboard usage stats."""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        from django.db.models import Count

        qs = LLMInteraction.objects.filter(user=request.user)
        total = qs.count()

        def _cnt(value):
            # Count rows whose status == value via a dedicated aggregation (avoids
            # loading the queryset twice for small tenants).
            return qs.filter(status=value).count()

        return Response(
            {
                "total_interactions": total,
                "blocked": _cnt("blocked"),
                "redacted": _cnt("redacted"),
                "violations": _cnt("violation"),
                "leaked_keys_detected": qs.filter(auto_deactivated=True).count(),
            }
        )
