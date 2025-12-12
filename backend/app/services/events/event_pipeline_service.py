# backend/app/services/events/event_pipeline_service.py

from datetime import datetime
from typing import Dict, Any

from app.schemas.events import EventIngestRequest, EventIngestResponse, IOCBundle
from app.schemas.correlation import CorrelationInput, CorrelationVerdict
from app.services.events.event_store_service import event_store_service
from app.services.correlation.correlation_engine import correlation_engine
from app.services.alerting.alert_dispatcher import dispatch_alerts

# If you already have these enrichment services, import them.
# Adjust module paths/names to your actual code.
from app.services.enrichment.ip_enrich_service import enrich_ips  # -> List[IPEnrichmentResult]
from app.services.enrichment.domain_enrich_service import enrich_domains  # -> List[DomainEnrichmentResult]
from app.services.enrichment.hash_enrich_service import enrich_hashes  # -> List[HashEnrichmentResult]

# Optional: if you want to reuse email_risk for email-type events later
# from app.services.risk_scoring.email_risk import compute_email_risk


class EventPipelineService:
    """
    End-to-end pipeline for a single ingested event:

      1. Store event (event_store_service)
      2. Extract IOCs
      3. Run IOC enrichment (IP/domain/hash)
      4. (Optionally) build TI context into raw_event
      5. Run correlation_engine
      6. Dispatch alerts based on CorrelationVerdict
      7. Return EventIngestResponse
    """

    def __init__(self) -> None:
        pass

    async def process_ingested_event(
        self, payload: EventIngestRequest
    ) -> EventIngestResponse:
        # 1) Store the event (in-memory for now; later DB)
        event_id = event_store_service.store_event(payload)

        # Pull back the stored dict so we have a single canonical copy
        event_dict = event_store_service.get_event(event_id)

        # 2) Extract IOCs from normalized bundle
        iocs: IOCBundle = payload.iocs
        src_ips = list(set(iocs.src_ips))
        dst_ips = list(set(iocs.dst_ips))
        domains = list(set(iocs.domains))
        hashes = list(set(iocs.hashes))

        # 3) Run IOC enrichment (you already have core logic & risk engines)
        #    These functions should internally call AbuseIPDB/IPInfo/DNS/VT etc
        #    and produce objects that include risk scores.
        ip_results = await enrich_ips(list(set(src_ips + dst_ips)))
        domain_results = await enrich_domains(domains)
        hash_results = await enrich_hashes(hashes)

        # 4) OPTIONAL: build threat-intel context into raw_event so that
        #    correlation_engine._rule_threat_intel_hits() can use it.
        #    You can refine this structure later.
        ti_ips: Dict[str, Any] = {}
        for ip_res in ip_results:
            ip = getattr(ip_res, "ip", None) or getattr(ip_res, "indicator", None)
            if not ip:
                continue
            # Example: map your enrichment schema into TI context expectations
            vt = getattr(ip_res, "virustotal", None)
            abuse = getattr(ip_res, "abuseipdb", None)
            ti_ips[ip] = {
                "vt_malicious": bool(getattr(vt, "malicious", False))
                or (getattr(getattr(vt, "risk", None), "severity", "") in ("high", "critical")),
                "abuseipdb_score": getattr(abuse, "score", None),
            }

        ti_domains: Dict[str, Any] = {}
        for d_res in domain_results:
            d = getattr(d_res, "domain", None) or getattr(d_res, "indicator", None)
            if not d:
                continue
            vt = getattr(d_res, "virustotal", None)
            vt_mal = False
            vt_cat = None
            if vt is not None:
                vt_mal = bool(getattr(vt, "malicious", False))
                vt_cat = getattr(vt, "category", None)
            ti_domains[d] = {
                "vt_malicious": vt_mal,
                "category": vt_cat,
            }

        ti_hashes: Dict[str, Any] = {}
        for h_res in hash_results:
            h = getattr(h_res, "hash", None) or getattr(h_res, "indicator", None)
            if not h:
                continue
            vt = getattr(h_res, "virustotal", None)
            vt_mal = False
            label = None
            if vt is not None:
                vt_mal = bool(
                    getattr(vt, "malicious", False)
                    or getattr(getattr(vt, "risk", None), "severity", "") in ("high", "critical")
                )
                label = getattr(vt, "label", None)
            ti_hashes[h] = {
                "vt_malicious": vt_mal,
                "label": label,
            }

        # Attach TI context into raw_event without losing original payload
        # (This is what correlation_engine._rule_threat_intel_hits expects.)
        raw_event = event_dict.get("raw_event") or {}
        ti_block = raw_event.get("ti") or {}
        ti_block.setdefault("ips", {}).update(ti_ips)
        ti_block.setdefault("domains", {}).update(ti_domains)
        ti_block.setdefault("hashes", {}).update(ti_hashes)
        raw_event["ti"] = ti_block
        event_dict["raw_event"] = raw_event

        # Persist the updated raw_event back to store (still in-memory for now)
        event_store_service._events[event_id] = event_dict  # ugly but fine for dev

        # 5) Build CorrelationInput and run correlation engine
        ci = CorrelationInput(
            event_id=event_id,
            extracted_iocs=iocs.dict(),  # {"src_ips": [...], "domains": [...], ...}
            raw_event=raw_event,
        )

        verdict: CorrelationVerdict = correlation_engine.correlate_event(ci)

        # 6) Dispatch alerts (Slack + generic webhook) based on risk_level
        dispatch_alerts(verdict, event_dict)

        # 7) Build and return response
        return EventIngestResponse(
            event_id=event_id,
            status="accepted",
            message="Event ingested, enriched, correlated, and alerting evaluated.",
            correlation=verdict,
        )


event_pipeline_service = EventPipelineService()
