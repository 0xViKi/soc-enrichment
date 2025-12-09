from app.schemas.hash_enrich import VTData, HashRiskScore, HashRiskFactor
from app.services.risk_scoring.risk_utils import severity_from_score


def compute_hash_risk(vt: VTData) -> HashRiskScore:
    factors = []

    # Detection percentage
    det_pct = vt.detection_percentage or 0
    factors.append(HashRiskFactor(
        name="vt_detection_percentage",
        weight=0.6,
        value=det_pct,
        contribution=det_pct * 0.6,
    ))

    # Reputation → risk mapping
    rep = vt.reputation if vt.reputation is not None else 0
    rep = max(min(rep, 100), -100)
    rep_risk = abs(rep) if rep <= 0 else (1 - rep / 100) * 50

    factors.append(HashRiskFactor(
        name="vt_reputation",
        weight=0.3,
        value=rep_risk,
        contribution=rep_risk * 0.3,
    ))

    # Placeholder for "family known"
    factors.append(HashRiskFactor(
        name="known_malware_family",
        weight=0.1,
        value=0.0,
        contribution=0.0,
    ))

    total = int(sum(f.contribution for f in factors))
    severity = severity_from_score(total)

    return HashRiskScore(score=total, severity=severity, factors=factors)
