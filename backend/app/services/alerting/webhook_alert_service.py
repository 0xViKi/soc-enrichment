# backend/app/services/alerting/webhook_alert_service.py
import logging
import requests

from app.schemas.correlation import CorrelationVerdict
from app.core.config import settings
from fastapi.encoders import jsonable_encoder

logger = logging.getLogger(__name__)

GENERIC_WEBHOOK_URL = settings.GENERIC_ALERT_WEBHOOK_URL


def send_generic_webhook_alert(verdict: CorrelationVerdict, event: dict) -> None:
    """
    Generic JSON webhook for n8n, custom dashboards, etc.

    Configure env:
      GENERIC_ALERT_WEBHOOK_URL=https://your-endpoint/ingest
    """
    if not GENERIC_WEBHOOK_URL:
        logger.info("Generic webhook URL not configured; skipping generic alert.")
        return

    payload = {
        "event_id": verdict.event_id,
        "risk_score": verdict.risk_score,
        "risk_level": verdict.risk_level,
        "findings": [f.dict() for f in verdict.findings],
        "event": {
            "source": event.get("source"),
            "severity": str(event.get("severity")),
            "vendor": event.get("vendor"),
            "product": event.get("product"),
            "event_type": event.get("event_type"),
            "description": event.get("description"),
            "occurred_at": event.get("occurred_at"),
            "iocs": event.get("iocs"),
        },
    }

    # Make it JSON-safe (datetimes → isoformat, enums → values, etc.)
    json_payload = jsonable_encoder(payload)

    try:
        resp = requests.post(GENERIC_WEBHOOK_URL, json=json_payload, timeout=5)
        resp.raise_for_status()
    except Exception as exc:
        logger.exception("Failed to send generic webhook alert: %s", exc)
