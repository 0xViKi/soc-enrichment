from typing import Any, Optional

import httpx

from app.core.config import settings


BASE_URL = "https://www.virustotal.com/api/v3"


async def fetch_vt_file(hash_value: str) -> Optional[dict[str, Any]]:
    """
    Look up a file by hash (md5/sha1/sha256) using VT v3 API.
    Returns the 'data' object or None.
    """
    api_key = settings.VIRUSTOTAL_API_KEY
    if not api_key:
        return None

    url = f"{BASE_URL}/files/{hash_value}"
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            data = resp.json()
            return data.get("data")
    except Exception:
        return None


async def fetch_vt_ip(ip: str) -> Optional[dict[str, Any]]:
    """
    Look up an IP address using VT v3 API.
    Returns the 'data' object or None.
    """
    api_key = settings.VIRUSTOTAL_API_KEY
    if not api_key:
        return None

    url = f"{BASE_URL}/ip_addresses/{ip}"
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            data = resp.json()
            return data.get("data")
    except Exception:
        return None

async def fetch_vt_domain(domain: str) -> Optional[dict[str, Any]]:
    """
    Look up a domain using VT v3 API.
    Returns the 'data' object or None.
    """
    api_key = settings.VIRUSTOTAL_API_KEY
    if not api_key:
        return None

    # VT expects bare domain (no protocol)
    domain = domain.strip().lower()
    url = f"{BASE_URL}/domains/{domain}"
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            data = resp.json()
            return data.get("data")
    except Exception:
        return None