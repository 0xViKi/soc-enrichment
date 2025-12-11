from typing import Any, Optional

import httpx

from app.config import settings


SEARCH_URL = "https://urlscan.io/api/v1/search/"


async def search_urlscan_domain(domain: str) -> Optional[dict[str, Any]]:
    """
    Use urlscan.io search API to find scans for a given domain.
    Returns raw JSON or None.
    """
    api_key = settings.URLSCAN_API_KEY
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["API-Key"] = api_key

    params = {"q": f"domain:{domain}"}

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(SEARCH_URL, headers=headers, params=params)
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            return resp.json()
    except Exception:
        return None
