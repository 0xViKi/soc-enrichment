# backend/app/services/enrichment/core_service/retry.py
from __future__ import annotations

import asyncio
import random
from typing import Awaitable, Callable, Optional, TypeVar

T = TypeVar("T")

def _is_retryable_exception(e: Exception) -> bool:
    # keep this broad; tighten later if you want
    name = type(e).__name__.lower()
    msg = str(e).lower()
    retry_keywords = [
        "timeout", "timed out", "temporarily unavailable",
        "connection reset", "connect", "socket", "dns",
        "server disconnected", "read error", "write error",
    ]
    return any(k in name for k in ["timeout", "connect", "network"]) or any(k in msg for k in retry_keywords)

async def async_retry(
    fn: Callable[[], Awaitable[T]],
    *,
    attempts: int = 3,
    base_delay: float = 0.6,
    max_delay: float = 4.0,
    jitter: float = 0.25,
    retry_if: Callable[[Exception], bool] = _is_retryable_exception,
) -> T:
    last_exc: Optional[Exception] = None

    for i in range(attempts):
        try:
            return await fn()
        except Exception as e:
            last_exc = e
            if i == attempts - 1 or not retry_if(e):
                raise

            # exponential backoff + jitter
            delay = min(max_delay, base_delay * (2 ** i))
            delay = delay * (1.0 + random.uniform(-jitter, jitter))
            await asyncio.sleep(max(0.0, delay))

    # should never reach
    raise last_exc or RuntimeError("async_retry failed without exception")
