# backend/app/services/correlation/correlation_engine.py
from typing import List
from datetime import datetime

from app.schemas.correlation import (
    CorrelationInput,
    CorrelationFinding,
    CorrelationVerdict,
)
from app.services.events.events_store_service import event_store_service


class CorrelationEngine:

    def __init__(self):
        pass

    def correlate_event(self, ci: CorrelationInput) -> CorrelationVerdict:
        """
        Core Phase 4 correlation method.
        This will grow significantly over time.
        """

        findings: List[CorrelationFinding] = []

        # === 1. Fetch event from store
        try:
            event = event_store_service.get_event(ci.event_id)
        except KeyError:
            raise RuntimeError(f"Event {ci.event_id} not found in store")

        iocs = ci.extracted_iocs

        # === 2. Gather historical events (we'll refine later)
        recent_events = event_store_service.list_events(limit=200)

        # === 3. Very simple placeholder correlation rule:
        # Repeated IP occurrence
        src_ips = iocs.get("src_ips", [])

        for ip in src_ips:
            count = sum(1 for ev in recent_events if ip in ev["iocs"].get("src_ips", []))

            if count > 1:
                findings.append(
                    CorrelationFinding(
                        type="repeated_ip",
                        description=f"IP {ip} has appeared in {count} events",
                        severity="medium",
                        metadata={"ip": ip, "count": count},
                    )
                )

        # === 4. Compute risk score (placeholder for now)
        risk_score = 20 + (15 * len(findings))
        risk_score = min(risk_score, 100)

        if risk_score < 30:
            risk_level = "low"
        elif risk_score < 60:
            risk_level = "medium"
        elif risk_score < 80:
            risk_level = "high"
        else:
            risk_level = "critical"

        return CorrelationVerdict(
            event_id=ci.event_id,
            risk_score=risk_score,
            risk_level=risk_level,
            findings=findings,
            timestamp=datetime.utcnow(),
        )


# Singleton instance (like other services)
correlation_engine = CorrelationEngine()
