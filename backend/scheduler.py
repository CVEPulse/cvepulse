import os
import json
import re
import requests
from datetime import datetime, timedelta, timezone
import feedparser

DATA_FILE = os.path.join(os.path.dirname(__file__), "data", "trending_cves.json")
NVD_API_KEY = os.getenv("NVD_API_KEY", None)

# ----------------------------
# Utility functions
# ----------------------------

def utcnow():
    return datetime.now(timezone.utc)

def parse_nvd_date(s: str):
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except:
        return None

def extract_cve_ids(text):
    return re.findall(r"CVE-\d{4}-\d{4,7}", text, flags=re.IGNORECASE)

# ----------------------------
# NEWS SOURCES
# ----------------------------

FEEDS = {
    "TheHackerNews": "https://feeds.feedburner.com/TheHackersNews",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "RedditNetsec": "https://www.reddit.com/r/netsec/.rss",
    "RedditCyber": "https://www.reddit.com/r/cybersecurity/.rss",
}

def collect_news_mentions():
    out = {}

    for source, url in FEEDS.items():
        print(f"[+] Fetching {source} …")
        feed = feedparser.parse(url)

        for entry in feed.entries:
            text = f"{entry.get('title', '')}\n{entry.get('summary', '')}"
            cves = extract_cve_ids(text)

            if not cves:
                continue

            # posted date
            if "published_parsed" in entry and entry.published_parsed:
                posted = datetime(*entry.published_parsed[:6], tzinfo=timezone.utc)
                posted_iso = posted.isoformat()
            else:
                posted_iso = "unknown"

            for cve in cves:
                cve_up = cve.upper()
                if cve_up not in out:
                    out[cve_up] = {
                        "id": cve_up,
                        "sources": set(),
                        "mentions": 0,
                        "posted": posted_iso,
                    }
                out[cve_up]["sources"].add(source)
                out[cve_up]["mentions"] += 1

    # convert sets → lists
    for k in out:
        out[k]["sources"] = list(out[k]["sources"])

    print(f"[✓] News/social mentions collected: {len(out)} CVEs")
    return out


# ----------------------------
# NVD FETCH
# ----------------------------

def fetch_nvd(days=7):
    now = utcnow()
    start = now - timedelta(days=days)

    params = {
        "resultsPerPage": 2000,
        "pubStartDate": start.isoformat(),
        "pubEndDate": now.isoformat(),
    }

    if NVD_API_KEY:
        params["apiKey"] = NVD_API_KEY

    print("[+] Fetching from NVD …")
    r = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params=params, timeout=20)

    if r.status_code != 200:
        print("[!] NVD fetch failed:", r.status_code)
        return {}

    data = r.json()
    out = {}

    for item in data.get("vulnerabilities", []):
        c = item.get("cve", {})
        cve_id = c.get("id")
        pub = parse_nvd_date(c.get("published"))
        if not cve_id:
            continue

        cvss = 0.0
        sev = "UNKNOWN"

        metrics = c.get("metrics", {})
        if "cvssMetricV31" in metrics:
            cvss = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
            sev = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
        elif "cvssMetricV30" in metrics:
            cvss = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
            sev = metrics["cvssMetricV30"][0]["cvssData"]["baseSeverity"]

        desc = c.get("descriptions", [{}])[0].get("value", "")

        out[cve_id] = {
            "id": cve_id,
            "description": desc,
            "published": pub.isoformat() if pub else "unknown",
            "cvss": cvss,
            "severity": sev.upper(),
        }

    print(f"[✓] NVD returned {len(out)} CVEs")
    return out


# ----------------------------
# TRENDING BUILDER
# ----------------------------

def build_trending():
    news = collect_news_mentions()
    nvd = fetch_nvd()

    merged = {}

    # merge NVD
    for cid, d in nvd.items():
        merged[cid] = {
            "id": cid,
            "description": d["description"],
            "published": d["published"],
            "cvss": d["cvss"],
            "severity": d["severity"],
            "sources": ["NVD"],
            "trend_score": 0,
        }

    # merge news/social
    for cid, d in news.items():
        if cid not in merged:
            merged[cid] = {
                "id": cid,
                "description": "(Mentioned in news/social sources)",
                "published": d["posted"],  # <-- important
                "cvss": 0.0,
                "severity": "UNKNOWN",
                "sources": d["sources"],
                "trend_score": d["mentions"],
            }
        else:
            merged[cid]["sources"] += d["sources"]
            merged[cid]["trend_score"] += d["mentions"]

    # convert dict → list
    final = list(merged.values())

    # trending sort: mentions + CVSS weight
    final.sort(key=lambda x: (x["trend_score"], x["cvss"]), reverse=True)

    return final


# ----------------------------
# RUN ONCE AND WRITE FILE
# ----------------------------

def run_once():
    print("=== CVEPulse Trending Builder ===")
    trending = build_trending()

    out = {
        "last_updated": utcnow().isoformat(),
        "count": len(trending),
        "cves": trending,
    }

    os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)

    print(f"[✓] Saved {len(trending)} CVEs → {DATA_FILE}")


if __name__ == "__main__":
    run_once()
