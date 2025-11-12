# backend/utils/priority_rules.py
import re
from typing import Dict, Any

MIN_EPSS_THREAT = 0.70
CVSS_CRIT = 9.0

# If True, vendor "emergency/out-of-band" wording can satisfy Step-1 threat (helps WSUS-like cases)
VENDOR_EMERGENCY_COUNTS_AS_THREAT = True

RCE_PRIV_PAT = re.compile(r"remote code execution|RCE|privilege escalation|full system compromise", re.I)
IMPACT_PAT   = re.compile(r"business[- ]critical|operational disruption|revenue loss|data breach", re.I)
INTERNET_PAT = re.compile(r"internet[- ]facing|exposed to internet|public[- ]facing", re.I)

def _sev_to_nums(sev: str) -> int:
    sev = (sev or "").lower()
    if sev.startswith("crit"): return 3
    if sev.startswith("high"): return 2
    if sev.startswith("med"):  return 1
    return 0

def classify_priority(rec: Dict[str, Any]) -> str:
    """
    Returns: 'Emergency', 'Zero-Day', 'Critical', 'High', 'Medium'
    rec fields used:
      - severity ('Critical'/'High'/...), cvss_score (float), description (str)
      - signals (list[str]) e.g., 'kev:list','exploited:wild','poc:credible','no-patch','keyword:emergency'
      - epss (float) optional
    """
    sigs = set(rec.get("signals") or [])
    sev  = (rec.get("severity") or "Medium")
    cvss = float(rec.get("cvss_score") or 0.0)
    desc = rec.get("description") or ""
    epss = float(rec.get("epss") or 0.0)

    # ---------- ZERO-DAY (your 5 bullets)
    zero_no_patch   = "no-patch" in sigs
    zero_newly_disc = True  # we approximate via recency filter in scheduler window
    zero_exploit_or_poc = ("exploited:wild" in sigs) or ("poc:credible" in sigs)
    zero_no_mit     = zero_no_patch  # best available proxy
    zero_vendor_unaware = False      # optional, not reliably detectable

    if zero_no_patch and zero_newly_disc and zero_exploit_or_poc and zero_no_mit:
        zero_day = True
    else:
        zero_day = False

    # ---------- EMERGENCY (Step-1 + Step-2)
    step1_threat = (
        ("kev:list" in sigs) or
        ("exploited:wild" in sigs) or
        (epss >= MIN_EPSS_THREAT) or
        (VENDOR_EMERGENCY_COUNTS_AS_THREAT and "keyword:emergency" in sigs)
    )

    # Step-2: need >= 3 of the following
    cond_rce_priv  = bool(RCE_PRIV_PAT.search(desc))
    cond_no_patch  = "no-patch" in sigs
    cond_cvss_crit = (cvss >= CVSS_CRIT) or (_sev_to_nums(sev) >= 2)  # org severity High/Critical counts
    # Heuristics for exposure/impact (optional text cues)
    cond_internet  = bool(INTERNET_PAT.search(desc))
    cond_impact_hi = bool(IMPACT_PAT.search(desc))

    step2_count = sum([cond_rce_priv, cond_internet, cond_no_patch, cond_cvss_crit, cond_impact_hi])
    emergency = step1_threat and (step2_count >= 3)

    # ---------- final label
    if emergency:
        return "Emergency"
    if zero_day:
        return "Zero-Day"
    # else severity mapping
    if _sev_to_nums(sev) >= 3 or cvss >= CVSS_CRIT:
        return "Critical"
    if _sev_to_nums(sev) >= 2:
        return "High"
    return "Medium"
