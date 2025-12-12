# backend/app/services/events/event_pipeline_service.py

from typing import Dict, Any, List

from app.schemas.events import EventIngestRequest, EventIngestResponse, IOCBundle
from app.schemas.correlation import CorrelationInput, CorrelationVerdict

from app.services.events.event_store_service import event_store_service
from app.services.correlation.correlation_engine import correlation_engine
from app.services.alerting.alert_dispatcher import dispatch_alerts

# Enrichment services
from app.services.enrichment.ip_enrich_service import enrich_ips    # -> List[IPEnrichResponse]
from app.services.enrichment.domain_enrich_service import enrich_domains  # -> List[DomainEnrichResponse]
from app.services.enrichment.hash_enrich_service import enrich_hashes     # -> List[HashEnrichResponse]


class EventPipelineService:
    """
    End-to-end pipeline for a single ingested event:

      1. Store event (DB)
      2. Extract IOCs (IPs / Domains / Hashes)
      3. Run IOC enrichment
      4. Build TI context into raw_event (for correlation engine)
      5. Persist updated raw_event back to DB
      6. Run correlation_engine
      7. Dispatch alerts
      8. Return EventIngestResponse
    """

    def __init__(self) -> None:
        pass

    async def process_ingested_event(
        self, payload: EventIngestRequest
    ) -> EventIngestResponse:
        # --------------------------------------------------
        # 1) Store the event
        # --------------------------------------------------
        event_id = event_store_service.store_event(payload)

        # Load it back as a dict so we have a single canonical copy
        event_dict = event_store_service.get_event(event_id)

        # --------------------------------------------------
        # 2) Extract IOCs
        # --------------------------------------------------
        iocs: IOCBundle = payload.iocs

        src_ips = list(set(iocs.src_ips))
        dst_ips = list(set(iocs.dst_ips))
        domains = list(set(iocs.domains))
        hashes = list(set(iocs.hashes))

        # --------------------------------------------------
        # 3) Run IOC enrichment
        #    Each enrich_* call should be tolerant of empty lists and
        #    return [] if nothing to enrich.
        # --------------------------------------------------
        all_ips: List[str] = list(set(src_ips + dst_ips))

        ip_results = await enrich_ips(all_ips) if all_ips else []
        domain_results = await enrich_domains(domains) if domains else []
        hash_results = await enrich_hashes(hashes) if hashes else []

        # --------------------------------------------------
        # 4) Build TI context for correlation_engine._rule_threat_intel_hits
        #
        #    raw_event["ti"] = {
        #       "ips": {
        #           "1.2.3.4": {
        #               "vt_malicious": bool,
        #               "abuseipdb_score": float | int | None
        #           },
        #       },
        #       "domains": {
        #           "example.com": {
        #               "vt_malicious": bool,
        #               "category": "phishing" | None,
        #           },
        #       },
        #       "hashes": {
        #           "abcdef...": {
        #               "vt_malicious": bool,
        #               "label": "trojan" | None,
        #           },
        #       },
        #    }
        # --------------------------------------------------
        ti_ips: Dict[str, Any] = {}
        for ip_res in ip_results:
            ip_value = getattr(ip_res, "value", None)
            if not ip_value:
                continue

            risk = getattr(ip_res, "risk", None)
            abuse = getattr(ip_res, "abuseipdb", None)

            vt_malicious = False
            if risk is not None:
                sev = getattr(risk, "severity", "") or ""
                vt_malicious = str(sev).lower() in ("high", "critical")

            abuse_score = None
            if abuse is not None:
                abuse_score = getattr(abuse, "score", None)

            ti_ips[ip_value] = {
                "vt_malicious": vt_malicious,
                "abuseipdb_score": abuse_score,
            }

        ti_domains: Dict[str, Any] = {}
        for d_res in domain_results:
            d_value = getattr(d_res, "value", None)
            if not d_value:
                continue

            risk = getattr(d_res, "risk", None)
            vt = getattr(d_res, "vt", None)

            vt_malicious = False
            if risk is not None:
                sev = getattr(risk, "severity", "") or ""
                vt_malicious = str(sev).lower() in ("high", "critical")

            category = None
            # VirusTotal domain categories is typically a list or dict of tags
            if vt is not None:
                cats = getattr(vt, "categories", None)
                if isinstance(cats, list) and cats:
                    category = cats[0]
                elif isinstance(cats, dict) and cats:
                    category = list(cats.keys())[0]

            ti_domains[d_value] = {
                "vt_malicious": vt_malicious,
                "category": category,
            }

        ti_hashes: Dict[str, Any] = {}
        for h_res in hash_results:
            h_value = getattr(h_res, "value", None)
            if not h_value:
                continue

            risk = getattr(h_res, "risk", None)
            vt = getattr(h_res, "vt", None)

            vt_malicious = False
            if risk is not None:
                sev = getattr(risk, "severity", "") or ""
                vt_malicious = str(sev).lower() in ("high", "critical")

            label = None
            if vt is not None:
                names = getattr(vt, "names", None)
                if isinstance(names, list) and names:
                    label = names[0]

            ti_hashes[h_value] = {
                "vt_malicious": vt_malicious,
                "label": label,
            }

        # Attach TI block into raw_event, preserving any existing content
        raw_event = event_dict.get("raw_event") or {}
        ti_block = raw_event.get("ti") or {}

        ti_block.setdefault("ips", {}).update(ti_ips)
        ti_block.setdefault("domains", {}).update(ti_domains)
        ti_block.setdefault("hashes", {}).update(ti_hashes)

        raw_event["ti"] = ti_block

        # Update in-memory copy used for correlation + alerting
        event_dict["raw_event"] = raw_event

        # Persist enriched raw_event back into the DB
        event_store_service.update_event_raw_event(event_id, raw_event)

        # --------------------------------------------------
        # 5) Run correlation engine
        # --------------------------------------------------
        ci = CorrelationInput(
            event_id=event_id,
            extracted_iocs=iocs.dict(),
            raw_event=raw_event,
        )
        verdict: CorrelationVerdict = correlation_engine.correlate_event(ci)

        # --------------------------------------------------
        # 6) Dispatch alerts
        # --------------------------------------------------
        dispatch_alerts(verdict, event_dict)

        # --------------------------------------------------
        # 7) Return API response
        # --------------------------------------------------
        return EventIngestResponse(
            event_id=event_id,
            status="accepted",
            message="Event ingested, enriched, correlated, and alerting evaluated.",
            correlation=verdict,
        )


event_pipeline_service = EventPipelineService()
