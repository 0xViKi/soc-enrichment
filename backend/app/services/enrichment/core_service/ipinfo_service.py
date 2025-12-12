from typing import Any, Optional

import httpx

from app.core.config import settings


BASE_URL = "https://ipinfo.io"


async def fetch_ipinfo(ip: str) -> Optional[dict[str, Any]]:
    """
    Call ipinfo.io /{ip} endpoint.
    Returns raw JSON data or None if disabled / failed.
    """
    token = settings.IPINFO_TOKEN
    if not token:
        return None

    url = f"{BASE_URL}/{ip}"
    params = {"token": token}

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            return resp.json()
    except Exception:
        return None
