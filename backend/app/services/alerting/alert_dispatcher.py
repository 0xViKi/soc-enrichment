# backend/app/services/alerting/alert_dispatcher.py
import logging

from app.schemas.correlation import CorrelationVerdict
from app.services.alerting.slack_alert_service import send_slack_alert
from app.services.alerting.webhook_alert_service import send_generic_webhook_alert

logger = logging.getLogger(__name__)


def dispatch_alerts(verdict: CorrelationVerdict, event: dict) -> None:
    """
    Central place to decide *when* to alert and which channels to use.
    For now:
      - Only HIGH / CRITICAL trigger alerts.
    """
    if verdict.risk_level not in ("high", "critical"):
        logger.info(
            "Risk level %s below alert threshold; no alerts sent.", verdict.risk_level
        )
        return

    logger.info(
        "Dispatching alerts for event %s (risk_level=%s)",
        verdict.event_id,
        verdict.risk_level,
    )

    # Fan-out to individual channels; failures shouldn't break the pipeline.
    try:
        send_slack_alert(verdict, event)
    except Exception:
        logger.exception("Slack alert failed.")

    try:
        send_generic_webhook_alert(verdict, event)
    except Exception:
        logger.exception("Generic webhook alert failed.")
