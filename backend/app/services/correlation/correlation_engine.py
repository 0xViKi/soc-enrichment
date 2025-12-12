# backend/app/services/correlation/correlation_engine.py
from typing import List
from datetime import datetime, timedelta

from app.schemas.correlation import (
    CorrelationInput,
    CorrelationFinding,
    CorrelationVerdict,
)
from backend.app.services.events.event_store_service import event_store_service


class CorrelationEngine:
    """
    Foundational correlation rules for Phase 4.

    Implemented rule groups:
      1. Repeated IP activity (any event type).
      2. SSH brute-force pattern: repeated ssh_fail events from same src_ip.
      3. New-domain correlation (uses domain age if available).
      4. Threat intel escalation (VT / AbuseIPDB style fields in raw_event).
      5. Email-oriented rules (SPF/DKIM/DMARC + suspicious links + new domain).

    NOTE: This engine assumes upstream components (email analysis / enrichment
    services) inject extra context into event['raw_event'], such as:
      - domain_age_days
      - vt_* verdicts
      - abuseipdb_score
      - email_security: {spf_result, dkim_result, dmarc_result, ...}
    """


    # Time windows (in minutes)
    REPEAT_IP_WINDOW_MINUTES = 15
    BRUTEFORCE_WINDOW_MINUTES = 10

    # Thresholds for IP repetition
    REPEAT_IP_MEDIUM_THRESHOLD = 5
    REPEAT_IP_HIGH_THRESHOLD = 15

    # Thresholds for brute force
    BRUTEFORCE_MEDIUM_THRESHOLD = 5
    BRUTEFORCE_HIGH_THRESHOLD = 10
    BRUTEFORCE_CRITICAL_THRESHOLD = 20

    # Thresholds for domain age (days)
    NEW_DOMAIN_HIGH_DAYS = 7
    NEW_DOMAIN_MEDIUM_DAYS = 30

    # Threat intel thresholds (examples)
    ABUSEIPDB_HIGH_SCORE = 75
    ABUSEIPDB_MEDIUM_SCORE = 50

    def __init__(self) -> None:
        pass

    # -------------------------------------------------------------------------
    # Public entry point
    # -------------------------------------------------------------------------
    def correlate_event(self, ci: CorrelationInput) -> CorrelationVerdict:
        """
        Core correlation method.

        Uses event store + basic rules to produce:
          - findings (list of CorrelationFinding)
          - risk_score (0–100)
          - risk_level (low/medium/high/critical)
        """
        try:
            event = event_store_service.get_event(ci.event_id)
        except KeyError:
            raise RuntimeError(f"Event {ci.event_id} not found in store")

        iocs = ci.extracted_iocs or {}
        raw_event = ci.raw_event or {}
        now = datetime.utcnow()

        recent_events = event_store_service.list_events(limit=500)

        findings: List[CorrelationFinding] = []

        # 1) Network / host based
        findings.extend(
            self._rule_repeated_ip_activity(event, iocs, recent_events, now)
        )
        findings.extend(
            self._rule_ssh_bruteforce(event, iocs, recent_events, now)
        )

        # 2) Domain / DNS based (new domain)
        findings.extend(
            self._rule_new_domain_age(event, iocs, raw_event)
        )

        # 3) Threat intel hits (VT / AbuseIPDB style in raw_event)
        findings.extend(
            self._rule_threat_intel_hits(event, iocs, raw_event)
        )

        # 4) Email-specific security rules (SPF/DKIM/DMARC + links)
        findings.extend(
            self._rule_email_security(event, iocs, raw_event)
        )

        risk_score = self._compute_risk_score(event, findings)
        risk_level = self._map_score_to_level(risk_score)

        return CorrelationVerdict(
            event_id=ci.event_id,
            risk_score=risk_score,
            risk_level=risk_level,
            findings=findings,
            timestamp=now,
        )

    # -------------------------------------------------------------------------
    # Rule 1: Repeated IP activity
    # -------------------------------------------------------------------------
    def _rule_repeated_ip_activity(
        self,
        event: dict,
        iocs: dict,
        recent_events: List[dict],
        now: datetime,
    ) -> List[CorrelationFinding]:
        findings: List[CorrelationFinding] = []

        src_ips = iocs.get("src_ips") or []
        if not src_ips:
            return findings

        window_start = now - timedelta(minutes=self.REPEAT_IP_WINDOW_MINUTES)

        for ip in src_ips:
            count = 0
            for ev in recent_events:
                occurred_at = ev.get("occurred_at")
                if isinstance(occurred_at, datetime) and occurred_at < window_start:
                    continue

                ev_iocs = ev.get("iocs") or {}
                ev_src_ips = ev_iocs.get("src_ips") or []
                if ip in ev_src_ips:
                    count += 1

            if count <= 1:
                continue

            if count >= self.REPEAT_IP_HIGH_THRESHOLD:
                severity = "high"
            elif count >= self.REPEAT_IP_MEDIUM_THRESHOLD:
                severity = "medium"
            else:
                severity = "low"

            findings.append(
                CorrelationFinding(
                    type="repeated_ip_activity",
                    description=(
                        f"Source IP {ip} has appeared in {count} events within the "
                        f"last {self.REPEAT_IP_WINDOW_MINUTES} minutes."
                    ),
                    severity=severity,
                    metadata={
                        "ip": ip,
                        "count": count,
                        "window_minutes": self.REPEAT_IP_WINDOW_MINUTES,
                    },
                )
            )

        return findings

    # -------------------------------------------------------------------------
    # Rule 2: SSH brute-force attempts (ssh_fail)
    # -------------------------------------------------------------------------
    def _rule_ssh_bruteforce(
        self,
        event: dict,
        iocs: dict,
        recent_events: List[dict],
        now: datetime,
    ) -> List[CorrelationFinding]:
        findings: List[CorrelationFinding] = []

        event_type = event.get("event_type")
        if event_type != "ssh_fail":
            return findings

        src_ips = iocs.get("src_ips") or []
        if not src_ips:
            return findings

        window_start = now - timedelta(minutes=self.BRUTEFORCE_WINDOW_MINUTES)

        for ip in src_ips:
            attempts = 0
            for ev in recent_events:
                occurred_at = ev.get("occurred_at")
                if isinstance(occurred_at, datetime) and occurred_at < window_start:
                    continue

                if ev.get("event_type") != "ssh_fail":
                    continue

                ev_iocs = ev.get("iocs") or {}
                ev_src_ips = ev_iocs.get("src_ips") or []
                if ip in ev_src_ips:
                    attempts += 1

            if attempts <= 1:
                continue

            if attempts >= self.BRUTEFORCE_CRITICAL_THRESHOLD:
                severity = "critical"
            elif attempts >= self.BRUTEFORCE_HIGH_THRESHOLD:
                severity = "high"
            elif attempts >= self.BRUTEFORCE_MEDIUM_THRESHOLD:
                severity = "medium"
            else:
                severity = "low"

            findings.append(
                CorrelationFinding(
                    type="ssh_bruteforce",
                    description=(
                        f"Detected {attempts} SSH failure events from {ip} within "
                        f"the last {self.BRUTEFORCE_WINDOW_MINUTES} minutes."
                    ),
                    severity=severity,
                    metadata={
                        "ip": ip,
                        "attempts": attempts,
                        "window_minutes": self.BRUTEFORCE_WINDOW_MINUTES,
                    },
                )
            )

        return findings

    # -------------------------------------------------------------------------
    # Rule 3: New-domain correlation (domain age)
    # -------------------------------------------------------------------------
    def _rule_new_domain_age(
        self,
        event: dict,
        iocs: dict,
        raw_event: dict,
    ) -> List[CorrelationFinding]:
        """
        Detect use of very new domains.

        Assumes upstream has added one of:
          - raw_event["domain_context"][domain]["age_days"]
          - raw_event["domain_age_days"] (for primary sender domain)
        """
        findings: List[CorrelationFinding] = []

        domains = iocs.get("domains") or []
        domain_ctx = raw_event.get("domain_context") or {}

        # 1) Per-IOC domains
        for d in domains:
            age_days = None

            ctx = domain_ctx.get(d) or {}
            if "age_days" in ctx:
                age_days = ctx.get("age_days")

            if age_days is None:
                continue

            try:
                age_days = float(age_days)
            except Exception:
                continue

            if age_days <= self.NEW_DOMAIN_HIGH_DAYS:
                severity = "high"
            elif age_days <= self.NEW_DOMAIN_MEDIUM_DAYS:
                severity = "medium"
            else:
                continue  # not "new" enough

            findings.append(
                CorrelationFinding(
                    type="new_domain",
                    description=(
                        f"Domain {d} is very new (age={age_days:.1f} days), "
                        f"used in current event."
                    ),
                    severity=severity,
                    metadata={"domain": d, "age_days": age_days},
                )
            )

        # 2) Primary/sender domain for email (if provided)
        sender_domain = raw_event.get("sender_domain")
        sender_age = raw_event.get("sender_domain_age_days")

        if sender_domain and sender_age is not None:
            try:
                sender_age = float(sender_age)
            except Exception:
                sender_age = None

        if sender_domain and sender_age is not None:
            if sender_age <= self.NEW_DOMAIN_HIGH_DAYS:
                severity = "high"
            elif sender_age <= self.NEW_DOMAIN_MEDIUM_DAYS:
                severity = "medium"
            else:
                severity = None

            if severity:
                findings.append(
                    CorrelationFinding(
                        type="new_sender_domain",
                        description=(
                            f"Email sender domain {sender_domain} is very new "
                            f"(age={sender_age:.1f} days)."
                        ),
                        severity=severity,
                        metadata={
                            "domain": sender_domain,
                            "age_days": sender_age,
                        },
                    )
                )

        return findings

    # -------------------------------------------------------------------------
    # Rule 4: Threat intel escalation (VT / AbuseIPDB, etc.)
    # -------------------------------------------------------------------------
    def _rule_threat_intel_hits(
        self,
        event: dict,
        iocs: dict,
        raw_event: dict,
    ) -> List[CorrelationFinding]:
        """
        Escalate severity when threat intel flags IOCs as malicious.

        Assumes upstream has added something like:
          raw_event["ti"] = {
            "ips": {
              "1.2.3.4": {
                "vt_malicious": True,
                "abuseipdb_score": 85
              },
              ...
            },
            "domains": {
              "example.com": {
                "vt_malicious": False,
                "category": "phishing"
              },
              ...
            },
            "hashes": {
              "abcdef...": {
                "vt_malicious": True,
                "label": "trojan"
              }
            }
          }
        """
        findings: List[CorrelationFinding] = []

        ti = raw_event.get("ti") or {}
        ip_ti = ti.get("ips") or {}
        domain_ti = ti.get("domains") or {}
        hash_ti = ti.get("hashes") or {}

        # IP threat intel
        for ip in iocs.get("src_ips") or []:
            ctx = ip_ti.get(ip) or {}
            vt_bad = bool(ctx.get("vt_malicious"))
            abuse_score = ctx.get("abuseipdb_score")

            # AbuseIPDB score escalation
            if abuse_score is not None:
                try:
                    abuse_score = float(abuse_score)
                except Exception:
                    abuse_score = None

            severity = None
            reasons = []

            if vt_bad:
                severity = "high"
                reasons.append("VirusTotal flags IP as malicious")

            if abuse_score is not None:
                if abuse_score >= self.ABUSEIPDB_HIGH_SCORE:
                    severity = "high"
                    reasons.append(f"AbuseIPDB score {abuse_score}")
                elif abuse_score >= self.ABUSEIPDB_MEDIUM_SCORE and severity is None:
                    severity = "medium"
                    reasons.append(f"AbuseIPDB score {abuse_score}")

            if severity:
                findings.append(
                    CorrelationFinding(
                        type="ip_threat_intel",
                        description=(
                            f"Threat intel flags IP {ip} as suspicious: "
                            + "; ".join(reasons)
                        ),
                        severity=severity,
                        metadata={"ip": ip, "ti": ctx},
                    )
                )

        # Domain threat intel
        for d in iocs.get("domains") or []:
            ctx = domain_ti.get(d) or {}
            vt_bad = bool(ctx.get("vt_malicious"))
            category = ctx.get("category")

            if not vt_bad and not category:
                continue

            if vt_bad:
                severity = "high"
            else:
                severity = "medium"

            desc_parts = []
            if vt_bad:
                desc_parts.append("VirusTotal flags domain as malicious")
            if category:
                desc_parts.append(f"Category={category}")

            findings.append(
                CorrelationFinding(
                    type="domain_threat_intel",
                    description=f"Threat intel for domain {d}: " + "; ".join(desc_parts),
                    severity=severity,
                    metadata={"domain": d, "ti": ctx},
                )
            )

        # Hash threat intel
        for h in iocs.get("hashes") or []:
            ctx = hash_ti.get(h) or {}
            vt_bad = bool(ctx.get("vt_malicious"))
            label = ctx.get("label")

            if not vt_bad:
                continue

            severity = "high"
            desc = f"File hash {h} flagged as malicious by VirusTotal"
            if label:
                desc += f" (label={label})"

            findings.append(
                CorrelationFinding(
                    type="hash_threat_intel",
                    description=desc,
                    severity=severity,
                    metadata={"hash": h, "ti": ctx},
                )
            )

        return findings

    # -------------------------------------------------------------------------
    # Rule 5: Email security (SPF/DKIM/DMARC + links + new domain)
    # -------------------------------------------------------------------------
    def _rule_email_security(
        self,
        event: dict,
        iocs: dict,
        raw_event: dict,
    ) -> List[CorrelationFinding]:
        """
        Email-oriented correlation:

        Looks for:
          - SPF / DKIM / DMARC failures
          - Suspicious links count
          - Combination with new sender domain
        """
        findings: List[CorrelationFinding] = []

        # Basic heuristic: this is an "email-ish" event if source/event_type mention it
        source = str(event.get("source") or "").lower()
        event_type = str(event.get("event_type") or "").lower()

        if "email" not in source and "email" not in event_type and "phish" not in event_type:
            # Not an email-related event, skip
            return findings

        email_sec = raw_event.get("email_security") or {}

        spf = (email_sec.get("spf_result") or "").lower()
        dkim = (email_sec.get("dkim_result") or "").lower()
        dmarc = (email_sec.get("dmarc_result") or "").lower()

        link_stats = raw_event.get("link_stats") or {}
        suspicious_links = int(link_stats.get("suspicious_links", 0))
        total_links = int(link_stats.get("total_links", 0))

        sender_domain = raw_event.get("sender_domain")
        sender_age = raw_event.get("sender_domain_age_days")

        # SPF/DKIM/DMARC combined finding
        fail_count = 0
        fails = []
        if spf and spf not in ("pass", "none"):
            fail_count += 1
            fails.append(f"SPF={spf}")
        if dkim and dkim not in ("pass", "none"):
            fail_count += 1
            fails.append(f"DKIM={dkim}")
        if dmarc and dmarc not in ("pass", "none"):
            fail_count += 1
            fails.append(f"DMARC={dmarc}")

        if fail_count >= 2:
            severity = "high"
        elif fail_count == 1:
            severity = "medium"
        else:
            severity = None

        if severity:
            findings.append(
                CorrelationFinding(
                    type="email_auth_failures",
                    description=(
                        "Email authentication issues detected: " + ", ".join(fails)
                    ),
                    severity=severity,
                    metadata={
                        "spf": spf,
                        "dkim": dkim,
                        "dmarc": dmarc,
                        "fail_count": fail_count,
                    },
                )
            )

        # Suspicious links finding
        if suspicious_links > 0:
            if suspicious_links >= 3:
                sev_links = "high"
            else:
                sev_links = "medium"

            findings.append(
                CorrelationFinding(
                    type="email_suspicious_links",
                    description=(
                        f"Email contains {suspicious_links} suspicious links "
                        f"(total_links={total_links})."
                    ),
                    severity=sev_links,
                    metadata={
                        "suspicious_links": suspicious_links,
                        "total_links": total_links,
                    },
                )
            )

        # Combo: new sender domain + auth failures OR suspicious links
        try:
            sender_age = float(sender_age) if sender_age is not None else None
        except Exception:
            sender_age = None

        if sender_domain and sender_age is not None and sender_age <= self.NEW_DOMAIN_MEDIUM_DAYS:
            # If we already had serious email findings, upgrade
            has_email_high = any(
                f.type in ("email_auth_failures", "email_suspicious_links")
                and f.severity in ("high", "critical")
                for f in findings
            )

            # If domain is extremely new, escalate aggressively
            if sender_age <= self.NEW_DOMAIN_HIGH_DAYS or has_email_high:
                combo_sev = "high"
            else:
                combo_sev = "medium"

            findings.append(
                CorrelationFinding(
                    type="email_new_sender_domain_combo",
                    description=(
                        f"Suspicious email from new sender domain {sender_domain} "
                        f"(age={sender_age:.1f} days) with additional risk indicators."
                    ),
                    severity=combo_sev,
                    metadata={
                        "domain": sender_domain,
                        "age_days": sender_age,
                    },
                )
            )

        return findings

    # -------------------------------------------------------------------------
    # Risk scoring
    # -------------------------------------------------------------------------
    def _compute_risk_score(
        self,
        event: dict,
        findings: List[CorrelationFinding],
    ) -> int:
        """
        Basic severity-weighted risk scoring.

        Components:
          - Base score from original event severity (from SIEM).
          - Additional score from correlation finding severities.
        """
        score = 0

        base_sev_raw = str(event.get("severity", "")).lower()
        if "critical" in base_sev_raw:
            score += 40
        elif "high" in base_sev_raw:
            score += 30
        elif "medium" in base_sev_raw:
            score += 20
        elif "low" in base_sev_raw:
            score += 10
        else:
            score += 5  # info / unknown

        for f in findings:
            sev = f.severity.lower()
            if sev == "critical":
                score += 45
            elif sev == "high":
                score += 30
            elif sev == "medium":
                score += 15
            elif sev == "low":
                score += 5

        score = max(0, min(score, 100))
        return score

    @staticmethod
    def _map_score_to_level(score: int) -> str:
        if score < 20:
            return "low"
        elif score < 50:
            return "medium"
        elif score < 80:
            return "high"
        else:
            return "critical"


correlation_engine = CorrelationEngine()
