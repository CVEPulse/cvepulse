"""
CVEPulse Scheduler
Fetches trending CVEs from NVD every cycle and saves them locally.
This version is fully Render-compatible and provides high → low sorting.
"""

import os
import json
import datetime
import requests


async def fetch_trending_cves(output_path: str):
    """
    Fetch recent CVEs from NVD and sort by CVSS v3 score (high → low).
    """
    print("=== CVEPulse Trending CVE Fetch ===")

    # Use NVD API (v2.0)
    NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    RESULTS_PER_PAGE = 200

    now = datetime.datetime.now(datetime.UTC)
    start_date = (now - datetime.timedelta(days=7)).isoformat()

    params = {
        "resultsPerPage": RESULTS_PER_PAGE,
        "pubStartDate": start_date,
        "pubEndDate": now.isoformat(),
        "sortBy": "publishDate",
    }

    print(f"[+] Fetching from NVD API with params: {params}")

    try:
        response = requests.get(NVD_URL, params=params, timeout=30)
        response.raise_for_status()
        data = response.json()
        items = data.get("vulnerabilities", [])
        print(f"[✓] Retrieved {len(items)} CVEs from NVD")
    except Exception as e:
        print(f"[!] NVD fetch failed: {e}")
        items = []

    cves = []
    for item in items:
        cve_data = item.get("cve", {})
        metrics = cve_data.get("metrics", {})

        # Try to find a valid CVSS base score
        cvss_score = 0
        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if key in metrics and metrics[key]:
                cvss_score = metrics[key][0].get("cvssData", {}).get("baseScore", 0)
                break

        published = cve_data.get("published", "N/A")
        description = cve_data.get("descriptions", [{}])[0].get("value", "No description provided.")

        cves.append({
            "id": cve_data.get("id", "N/A"),
            "cvss": cvss_score,
            "description": description,
            "source": "NVD",
            "published": published,
        })

    # Sort by severity and then recency
    cves.sort(key=lambda x: (x["cvss"], x["published"]), reverse=True)

    output = {
        "last_updated": now.isoformat(),
        "count": len(cves),
        "cves": cves,
    }

    # Ensure directory exists
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # Save trending CVEs
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print(f"[✓] Wrote {len(cves)} CVEs → {output_path}")
    print("=== CVEPulse Scheduler Finished ===")
