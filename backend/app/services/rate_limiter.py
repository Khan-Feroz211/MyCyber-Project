from __future__ import annotations

import os
import logging
from typing import Optional

try:
    from redis import asyncio as redis_async
except Exception:  # pragma: no cover - optional dependency
    redis_async = None

_logger = logging.getLogger(__name__)


async def check_rate_limit(user_id: int) -> None:
    """Enforce a simple per-user per-minute rate limit using Redis when configured.

    Raises HTTPException on limit exceeded. If Redis is not configured, no-op.
    """
    from fastapi import HTTPException, status

    REDIS_URL = os.getenv("REDIS_URL", "")
    if not REDIS_URL or redis_async is None:
        return

    limit = int(os.getenv("RATE_LIMIT_PER_MIN", "60"))
    key = f"rate:{user_id}:{int(__import__('time').time() // 60)}"

    try:
        r = redis_async.from_url(REDIS_URL)
        # Use atomic INCR with EXPIRE semantics
        cur = await r.incr(key)
        if cur == 1:
            await r.expire(key, 60)
        if cur > limit:
            _logger.warning("Rate limit exceeded for user %s: %s requests", user_id, cur)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded: {limit} requests per minute.",
            )
    except HTTPException:
        raise
    except Exception as exc:  # pragma: no cover
        _logger.exception("Rate limiter error: %s", exc)
        return
