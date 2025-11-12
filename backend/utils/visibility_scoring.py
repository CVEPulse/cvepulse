# backend/utils/visibility_scoring.py
"""
CVEPulse Contextual Visibility Scoring Module
Integrates feed data (NVD + news + community) to compute visibility insights.
Author: Mayank Upadhyay
"""

from typing import List, Dict

# --------------------------------------------
# 1️⃣ Define Source Weights
# --------------------------------------------
SOURCE_TIERS = {
    "NVD": 5, "CISA": 5, "MITRE": 5, "CERT": 5,  # Tier 1
    "The Hacker News": 3, "BleepingComputer": 3, "SecurityWeek": 3,  # Tier 2
    "Reddit": 1.5, "HackerNews": 1.5, "Twitter": 1.5, "X": 1.5, "Mastodon": 1.5  # Tier 3
}

# --------------------------------------------
# 2️⃣ Compute Weighted Visibility Score
# --------------------------------------------
def calculate_visibility_score(sources: List[str]) -> float:
    """Return weighted visibility score based on mention sources."""
    score = 0.0
    for src in sources:
        score += SOURCE_TIERS.get(src, 1)  # default minimal weight if unknown
    return round(score, 2)

# --------------------------------------------
# 3️⃣ Determine Visibility Category
# --------------------------------------------
def get_visibility_category(score: float) -> str:
    """Categorize visibility score into descriptive levels."""
    if score >= 12:
        return "Highly Discussed"
    elif 6 <= score < 12:
        return "Moderately Discussed"
    else:
        return "Emerging"

# --------------------------------------------
# 4️⃣ Generate Visibility Tag & Optional Color
# --------------------------------------------
def get_visibility_tag(score: float) -> Dict[str, str]:
    """Return color + label tuple for frontend rendering."""
    category = get_visibility_category(score)
    tag_color = {
        "Highly Discussed": "red",
        "Moderately Discussed": "orange",
        "Emerging": "yellow"
    }[category]
    return {"label": category, "color": tag_color}

# --------------------------------------------
# 5️⃣ Combine Visibility With CVE Record
# --------------------------------------------
def enrich_cve_record(cve: Dict) -> Dict:
    """
    Integrate visibility logic into a single CVE dictionary.
    Keeps Emergency / Zero-Day untouched, just adds context.
    """
    sources = cve.get("mentions", [])
    score = calculate_visibility_score(sources)
    category = get_visibility_category(score)
    tag = get_visibility_tag(score)

    # Do not override Emergency / Zero-Day classification
    priority = cve.get("priority", "Unknown")

    # Optional contextual upgrades (non-emergency)
    if priority == "Critical" and category == "Highly Discussed":
        priority = "Emergency"
    elif priority == "High" and category == "Highly Discussed":
        priority = "Critical"

    cve.update({
        "visibility_score": score,
        "visibility_label": category,
        "visibility_tag": tag,
        "priority": priority,
    })
    return cve
