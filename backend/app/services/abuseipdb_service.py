from typing import Any, Optional

import httpx

from app.config import settings


BASE_URL = "https://api.abuseipdb.com/api/v2/check"


async def fetch_abuseipdb(ip: str) -> Optional[dict[str, Any]]:
    """
    Call AbuseIPDB check endpoint.
    Returns raw JSON data or None if disabled / failed.
    """
    api_key = settings.ABUSEIPDB_API_KEY
    if not api_key:
        return None

    headers = {"Key": api_key, "Accept": "application/json"}
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
        "verbose": True,
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(BASE_URL, headers=headers, params=params)
            resp.raise_for_status()
            data = resp.json()
            return data.get("data") or data
    except Exception:
        # For lab use, just swallow and return None; you can log later
        return None
