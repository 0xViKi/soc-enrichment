# backend/app/services/alerting/slack_alert_service.py
import logging
import requests

from app.schemas.correlation import CorrelationVerdict
from app.core.config import settings
from fastapi.encoders import jsonable_encoder

logger = logging.getLogger(__name__)

SLACK_WEBHOOK_URL = settings.SLACK_ALERT_WEBHOOK_URL


def send_slack_alert(verdict: CorrelationVerdict, event: dict) -> None:
    """
    Simple Slack alert sender using Incoming Webhook URL.

    Configure env:
      SLACK_ALERT_WEBHOOK_URL=https://hooks.slack.com/services/...
    """
    if not SLACK_WEBHOOK_URL:
        logger.info("Slack webhook URL not configured; skipping Slack alert.")
        return

    text_lines = [
        ":rotating_light: *High-risk event detected*",
        f"*Event ID*: `{verdict.event_id}`",
        f"*Risk level*: `{verdict.risk_level}` (score {verdict.risk_score})",
    ]

    desc = event.get("description")
    if desc:
        text_lines.append(f"*Description*: {desc}")

    src = event.get("source")
    product = event.get("product")
    if src or product:
        text_lines.append(f"*Source*: `{src}` / `{product}`")

    if verdict.findings:
        text_lines.append("")
        text_lines.append("*Findings:*")
        for f in verdict.findings[:5]:
            text_lines.append(f"• `{f.severity}` – {f.description}")

    payload = {"text": "\n".join(text_lines)}

    # Make it JSON-safe (datetimes → isoformat, enums → values, etc.)
    json_payload = jsonable_encoder(payload)

    try:
        resp = requests.post(SLACK_WEBHOOK_URL, json=json_payload, timeout=5)
        resp.raise_for_status()
    except Exception as exc:
        logger.exception("Failed to send Slack alert: %s", exc)
