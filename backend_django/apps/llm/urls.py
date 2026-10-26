"""LLM-DLP pipeline routes (migrated from backend/app/routers/llm_dlp.py)."""
from __future__ import annotations

from django.urls import path

from apps.llm.views import (
    LlmChatAPI,
    LlmHistoryAPI,
    LlmInteractionDetailAPI,
    LlmStatsAPI,
)

app_name = "llm"

urlpatterns = [
    path("chat", LlmChatAPI.as_view(), name="chat"),
    path("history", LlmHistoryAPI.as_view(), name="history"),
    path("history/<interaction_id>", LlmInteractionDetailAPI.as_view(), name="interaction-detail"),
    path("stats", LlmStatsAPI.as_view(), name="stats"),
]
