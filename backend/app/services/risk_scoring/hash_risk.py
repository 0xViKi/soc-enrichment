from datetime import datetime
from typing import Optional, List

from app.schemas.enrich.hash_enrich import (
    VTData,
    HashRiskScore,
    HashRiskFactor,
)
from app.services.risk_scoring.risk_utils import severity_from_score


# ---------------------------------------------
# Helper functions
# ---------------------------------------------


def _normalize(value, min_v, max_v):
    if value is None:
        return 0
    try:
        v = float(value)
        return max(min((v - min_v) / (max_v - min_v), 1.0), 0.0) * 100
    except Exception:
        return 0


def _detection_strength(vt: VTData) -> float:
    """
    Weighted malicious detections considering:
    - number of vendors
    - number of high-quality vendors detecting it
    """
    if not vt or not vt.last_analysis_stats:
        return 0.0

    mal = vt.last_analysis_stats.malicious or 0
    suspicious = vt.last_analysis_stats.suspicious or 0
    undetected = vt.last_analysis_stats.undetected or 0
    harmless = vt.last_analysis_stats.harmless or 0

    total = mal + suspicious + undetected + harmless
    if total <= 0:
        return 0.0

    # Malicious vendors weighted 1.0, suspicious ~0.5
    score = ((mal * 1.0) + (suspicious * 0.5)) / total
    return score * 100.0


def _reputation_risk(rep: Optional[int]) -> float:
    """
    VT reputation (-100 to +100).
    Negative means malicious, positive means safe.
    """
    if rep is None:
        return 40.0  # Unknown = moderate risk

    rep = max(min(rep, 100), -100)

    if rep < 0:
        # Negative reputation directly scales risk
        return abs(rep)
    else:
        # Positive reputation reduces risk but not to zero
        return max(0, 50 - (rep * 0.3))


def _malware_family_risk(names: Optional[List[str]]) -> float:
    """
    Assign extra risk if family matches known active malware variants.
    """
    if not names:
        return 0.0

    high_risk_families = [
        "agenttesla",
        "lokibot",
        "redline",
        "qakbot",
        "emotet",
        "formbook",
        "async",
        "remcos",
        "rat",
        "trojan",
        "backdoor",
        "infostealer",
    ]

    name_l = " ".join(n.lower() for n in names)

    for fam in high_risk_families:
        if fam in name_l:
            return 90.0

    # If multiple vendors agree on a family → elevated confidence
    if len(names) >= 3:
        return 50.0
    if len(names) == 2:
        return 35.0

    return 20.0


def _file_behavior_risk(vt: VTData) -> float:
    """
    Inspect crowdsourced YARA, IDS, sigma-like behavior.
    """
    risk = 0.0

    # Crowdsourced YARA
    yara = getattr(vt, "crowdsourced_yara_results", None) or []
    if yara:
        risk += 10 * len(yara)
        if len(yara) > 3:
            risk += 20

    # Crowdsourced IDS (network behavior)
    ids = getattr(vt, "crowdsourced_ids_results", None) or []
    if ids:
        risk += 8 * len(ids)

    return min(risk, 100.0)


def _first_seen_risk(vt: VTData) -> float:
    """
    New malware samples are more dangerous.
    """
    first_seen = getattr(vt, "first_seen", None)
    if not first_seen:
        return 30.0

    try:
        dt = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
        days = (datetime.utcnow() - dt).days

        if days <= 1:
            return 100.0
        if days <= 7:
            return 80.0
        if days <= 30:
            return 50.0
        if days <= 180:
            return 20.0
        return 10.0
    except:
        return 30.0


def _file_type_mismatch_risk(vt: VTData) -> float:
    """
    Example: A file declared as PDF but actually contains PE header.
    """
    real = getattr(vt, "type_tag", "") or ""
    identified = getattr(vt, "file_type", "") or ""

    real_l = real.lower()
    ident_l = identified.lower()

    if "elf" in real_l or "pe" in real_l:
        if not any(x in ident_l for x in ("exe", "binary", "program")):
            return 90.0

    if "pdf" in ident_l and ("javascript" in real_l or "script" in real_l):
        return 70.0

    if "doc" in ident_l and "macro" in real_l:
        return 60.0

    return 0.0


def _pe_entropy_risk(vt: VTData) -> float:
    """
    High entropy indicates packing or obfuscation.
    """
    entropy = getattr(vt, "entropy", None)
    if entropy is None:
        return 0.0

    # Typical executable entropy range 6.5–8.0; > 7.5 often indicates packers.
    if entropy >= 7.5:
        return 90.0
    if entropy >= 7.0:
        return 70.0
    if entropy >= 6.7:
        return 40.0

    return 10.0


# ---------------------------------------------
# Main API
# ---------------------------------------------


def compute_hash_risk(vt: VTData) -> HashRiskScore:
    """
    SOC-grade malware hash scoring:
    - Detection spread
    - Reputation
    - Malware family classification
    - Behavior indicators
    - File type mismatch
    - Entropy (packer/obfuscation)
    - First seen age
    """

    factors = []

    # -------------------------
    # 1. AV Detection Strength
    # -------------------------
    det_strength = _detection_strength(vt)
    factors.append(HashRiskFactor(
        name="detection_strength",
        weight=0.30,
        value=det_strength,
        contribution=det_strength * 0.30,
    ))

    # -------------------------
    # 2. Reputation
    # -------------------------
    rep_risk = _reputation_risk(getattr(vt, "reputation", None))
    factors.append(HashRiskFactor(
        name="vt_reputation",
        weight=0.20,
        value=rep_risk,
        contribution=rep_risk * 0.20,
    ))

    # -------------------------
    # 3. Malware Family Classification
    # -------------------------
    family_risk = _malware_family_risk(getattr(vt, "names", None))
    factors.append(HashRiskFactor(
        name="malware_family",
        weight=0.20,
        value=family_risk,
        contribution=family_risk * 0.20,
    ))

    # -------------------------
    # 4. Behavior Indicators
    # -------------------------
    behavior_risk = _file_behavior_risk(vt)
    factors.append(HashRiskFactor(
        name="behavioral_indicators",
        weight=0.10,
        value=behavior_risk,
        contribution=behavior_risk * 0.10,
    ))

    # -------------------------
    # 5. File Type Mismatch
    # -------------------------
    mismatch_risk = _file_type_mismatch_risk(vt)
    factors.append(HashRiskFactor(
        name="file_type_mismatch",
        weight=0.08,
        value=mismatch_risk,
        contribution=mismatch_risk * 0.08,
    ))

    # -------------------------
    # 6. Entropy / Packer Detection
    # -------------------------
    entropy_risk = _pe_entropy_risk(vt)
    factors.append(HashRiskFactor(
        name="high_entropy_obfuscation",
        weight=0.07,
        value=entropy_risk,
        contribution=entropy_risk * 0.07,
    ))

    # -------------------------
    # 7. First Seen (Freshness)
    # -------------------------
    first_seen_risk = _first_seen_risk(vt)
    factors.append(HashRiskFactor(
        name="first_seen_recent",
        weight=0.05,
        value=first_seen_risk,
        contribution=first_seen_risk * 0.05,
    ))

    # -------------------------
    # Aggregate & final severity
    # -------------------------
    total = int(sum(f.contribution for f in factors))
    severity = severity_from_score(total)

    return HashRiskScore(score=total, severity=severity, factors=factors)
