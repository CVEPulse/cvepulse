import os
import re
import json
import requests
import feedparser
from datetime import datetime, timedelta, timezone

DATA_FILE = os.path.join(os.path.dirname(__file__), "data", "trending_cves.json")

# -------------------------------------------
# Helper: Extract CVE IDs from text
# -------------------------------------------

def extract_cves(text: str):
    """Return a unique list of CVE IDs found in a string."""
    return list(set(re.findall(r"CVE-\d{4}-\d{4,7}", text or "")))


# -------------------------------------------
# Fetch CVEs from external feeds
# -------------------------------------------

def safe_parse_feed(url: str, label: str):
    """Parse RSS/Atom feed, catch network errors gracefully."""
    try:
        print(f"[+] Scanning feed: {label}")
        return feedparser.parse(url)
    except Exception as e:
        print(f"[!] Feed error for {label}: {e}")
        return feedparser.parse("")


def fetch_bleepingcomputer():
    feed = safe_parse_feed("https://www.bleepingcomputer.com/feed/", "BleepingComputer")
    cves = []
    for e in feed.entries[:20]:
        cves += extract_cves(e.title)
    return list(set(cves))


def fetch_hackernews():
    feed = safe_parse_feed("https://thehackernews.com/feeds/posts/default", "TheHackerNews")
    cves = []
    for e in feed.entries[:20]:
        cves += extract_cves(e.title)
    return list(set(cves))


def fetch_reddit(subreddit, label=None):
    label = label or f"r/{subreddit}"
    feed = safe_parse_feed(f"https://www.reddit.com/r/{subreddit}/.rss", label)
    cves = []
    for e in feed.entries[:30]:
        title = getattr(e, "title", "")
        summary = getattr(e, "summary", "")
        cves += extract_cves(title)
        cves += extract_cves(summary)
    return list(set(cves))


# -------------------------------------------
# Fetch from NVD using API Key
# -------------------------------------------

def fetch_nvd():
    """Fetch last 7 days of CVEs from NVD."""
    api_key = os.environ.get("NVD_API_KEY")
    now = datetime.now(timezone.utc)
    start_date = (now - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    end_date = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "resultsPerPage": 100,
        "pubStartDate": start_date,
        "pubEndDate": end_date,
    }
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    print(f"[NVD] Fetching with API key configured: {bool(api_key)}")
    print(f"[NVD] Window: {start_date} → {end_date}")

    try:
        resp = requests.get(base_url, params=params, headers=headers, timeout=20)
        resp.raise_for_status()
    except Exception as e:
        print(f"[NVD ERROR] {e}")
        return []

    js = resp.json()
    vulns = js.get("vulnerabilities", [])
    print(f"[NVD] Retrieved {len(vulns)} CVEs")

    cve_list = []
    for item in vulns:
        meta = item.get("cve", {})
        cve_id = meta.get("id")
        descs = meta.get("descriptions", [])
        desc = descs[0].get("value", "") if descs else ""
        published = meta.get("published", "Unknown")

        metrics = meta.get("metrics", {})
        cvss = 0.0
        try:
            if "cvssMetricV31" in metrics:
                cvss = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV30" in metrics:
                cvss = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV2" in metrics:
                cvss = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
        except Exception:
            cvss = 0.0

        cve_list.append({
            "id": cve_id,
            "description": desc,
            "published": published,
            "cvss": float(cvss or 0.0),
            "sources": ["NVD"],
            "trend_score": 0,
        })

    return cve_list


# -------------------------------------------
# Merge + score trending
# -------------------------------------------

def merge_trending():
    print("=== Collecting feeds ===")

    nvd_list = fetch_nvd()

    # External “noise” sources
    bc = fetch_bleepingcomputer()
    hn = fetch_hackernews()
    r_netsec = fetch_reddit("netsec", "RedditNetsec")
    r_cyber = fetch_reddit("cybersecurity", "RedditCyber")

    source_map = {
        "BleepingComputer": set(bc),
        "TheHackerNews": set(hn),
        "RedditNetsec": set(r_netsec),
        "RedditCyber": set(r_cyber),
    }

    trending = []

    for cve in nvd_list:
        cve_id = cve["id"]
        cvss = cve["cvss"]

        sources = ["NVD"]
        mention_score = 0

        for src_name, cve_ids in source_map.items():
            if cve_id in cve_ids:
                mention_score += 1
                sources.append(src_name)

        # Severity boost (Critical > High > Medium)
        severity_boost = 0
        if cvss >= 9.0:
            severity_boost = 2
        elif cvss >= 7.0:
            severity_boost = 1

        trend_score = mention_score + severity_boost

        cve["sources"] = sources
        cve["trend_score"] = trend_score

        # INCLUSION RULE:
        #  - Any CVE with CVSS >= 7.0 (High/Critical)
        #  - OR any CVE mentioned in external sources
        if cvss >= 7.0 or mention_score > 0:
            trending.append(cve)

    # Sorting: higher trend_score → higher CVSS → newer publish date
    def parse_dt(s):
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
        except Exception:
            return datetime.min.replace(tzinfo=timezone.utc)

    trending.sort(
        key=lambda x: (
            x.get("trend_score", 0),
            x.get("cvss", 0.0),
            parse_dt(x.get("published", "1970-01-01T00:00:00"))
        ),
        reverse=True,
    )

    print(f"[TRENDING] Total after scoring/filtering: {len(trending)}")
    return trending


# -------------------------------------------
# Save JSON for API/frontend
# -------------------------------------------

def save_json(data):
    os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


# -------------------------------------------
# Main
# -------------------------------------------

if __name__ == "__main__":
    print("=== CVEPulse Trending Builder ===")
    trending = merge_trending()

    payload = {
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "count": len(trending),
        "cves": trending,
    }

    save_json(payload)
    print(f"✓ Trending CVEs saved → {DATA_FILE}")
    print(f"✓ Total trending: {len(trending)}")
