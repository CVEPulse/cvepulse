def enrich_cve_data(cve_item):
    cve = cve_item.get("cve", {})
    return {
        "id": cve.get("id", "CVE-Unknown"),
        "description": cve.get("descriptions", [{}])[0].get("value", "No description available"),
        "cvss": cve_item.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", 0),
        "published": cve_item.get("published", "Unknown")
    }
