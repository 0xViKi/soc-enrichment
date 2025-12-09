from datetime import datetime
from typing import Any, Optional

import whois


def _parse_date(value: Any) -> Optional[datetime]:
    if isinstance(value, list) and value:
        value = value[0]
    if isinstance(value, datetime):
        return value
    return None


def _compute_domain_age_days(created: Optional[datetime]) -> Optional[int]:
    if not created:
        return None
    now = datetime.utcnow()
    delta = now - created
    return delta.days


def _detect_privacy(raw: dict[str, Any]) -> Optional[bool]:
    # Heuristic: if registrant fields look like privacy / redacted
    privacy_keywords = ["privacy", "redacted", "protected", "whoisguard"]
    for key in ["org", "name", "registrant_name", "registrant_org"]:
        value = raw.get(key)
        if not value:
            continue
        if isinstance(value, list):
            value = " ".join(str(v).lower() for v in value)
        else:
            value = str(value).lower()
        if any(k in value for k in privacy_keywords):
            return True
    return None


def fetch_whois(domain: str) -> Optional[dict[str, Any]]:
    """
    Perform WHOIS lookup using python-whois.
    Returns a raw dict or None on failure.
    """
    try:
        data = whois.whois(domain)
        # python-whois returns a dict-like object
        return dict(data)
    except Exception:
        return None


def normalize_whois(domain: str) -> dict[str, Any]:
    """
    Wrapper: fetch whois + compute age + privacy flag.
    Returns normalized fields.
    """
    raw = fetch_whois(domain)
    if not raw:
        return {
            "enabled": False,
            "raw": None,
        }

    created = _parse_date(raw.get("creation_date"))
    updated = _parse_date(raw.get("updated_date"))
    expires = _parse_date(raw.get("expiration_date"))
    age_days = _compute_domain_age_days(created)
    privacy = _detect_privacy(raw)

    return {
        "enabled": True,
        "registrar": raw.get("registrar"),
        "creation_date": created.isoformat() if created else None,
        "expiration_date": expires.isoformat() if expires else None,
        "updated_date": updated.isoformat() if updated else None,
        "domain_name": raw.get("domain_name"),
        "raw": raw,
        "domain_age_days": age_days,
        "privacy_protected": privacy,
    }
