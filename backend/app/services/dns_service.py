from typing import List, Optional, Tuple

import dns.resolver


async def resolve_a_records(ip_or_host: str) -> tuple[list[str], Optional[str]]:
    """
    For IPs, return empty. For hostnames, try to get A records.
    Used by IP enrichment for now.
    """
    if all(ch.isdigit() or ch in ".:" for ch in ip_or_host):
        # Looks like pure IP, no DNS lookup
        return [], None

    resolver = dns.resolver.Resolver()
    try:
        answers = resolver.resolve(ip_or_host, "A")
        a_records: List[str] = [str(rdata.address) for rdata in answers]
        return a_records, None
    except Exception as e:
        return [], str(e)


async def resolve_dns_records(domain: str) -> dict:
    """
    Resolve A, MX, and TXT records for a domain.
    Returns a dict with lists + optional error fields.
    """
    resolver = dns.resolver.Resolver()
    result = {
        "a_records": [],
        "mx_records": [],
        "txt_records": [],
        "errors": {},
    }

    # A records
    try:
        answers = resolver.resolve(domain, "A")
        result["a_records"] = [str(r.address) for r in answers]
    except Exception as e:
        result["errors"]["A"] = str(e)

    # MX records
    try:
        answers = resolver.resolve(domain, "MX")
        result["mx_records"] = [str(r.exchange).rstrip(".") for r in answers]
    except Exception as e:
        result["errors"]["MX"] = str(e)

    # TXT records
    try:
        answers = resolver.resolve(domain, "TXT")
        txt_values: list[str] = []
        for r in answers:
            # r.strings is a tuple of bytes
            parts = [p.decode("utf-8", errors="ignore") for p in r.strings]
            txt_values.append("".join(parts))
        result["txt_records"] = txt_values
    except Exception as e:
        result["errors"]["TXT"] = str(e)

    return result
