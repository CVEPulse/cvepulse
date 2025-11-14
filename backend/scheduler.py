import os
import re
import json
import requests
import feedparser
from datetime import datetime, timedelta

DATA_FILE = os.path.join(os.path.dirname(__file__), "data", "trending_cves.json")

# -------------------------------------------
# Helper: Extract CVE IDs from text
# -------------------------------------------
def extract_cves(text):
    return list(set(re.findall(r"CVE-\d{4}-\d{4,7}", text)))


# -------------------------------------------
# Fetch CVEs from external feeds
# -------------------------------------------

def fetch_bleepingcomputer():
    url = "https://www.bleepingcomputer.com/feed/"
    feed = feedparser.parse(url)
    cves = []
    for e in feed.entries[:12]:
        cves += extract_cves(e.title)
    return list(set(cves))


def fetch_hackernews():
    url = "https://thehackernews.com/feeds/posts/default"
    feed = feedparser.parse(url)
    cves = []
    for e in feed.entries[:12]:
        cves += extract_cves(e.title)
    return list(set(cves))


def fetch_reddit(subreddit):
    url = f"https://www.reddit.com/r/{subreddit}/.rss"
    feed = feedparser.parse(url)
    cves = []
    for e in feed.entries[:12]:
        cves += extract_cves(e.title)
    return list(set(cves))


# -------------------------------------------
# Fetch from NVD using API Key
# -------------------------------------------
def fetch_nvd():
    api_key = os.environ.get("NVD_API_KEY", None)

    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    now = datetime.utcnow()
    start_date = (now - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    end_date = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    params = {
        "resultsPerPage": 100,
        "pubStartDate": start_date,
        "pubEndDate": end_date
    }

    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    print(f"Fetching NVD with API key: {bool(api_key)}")

    try:
        resp = requests.get(base_url, params=params, headers=headers, timeout=15)
        resp.raise_for_status()
        js = resp.json()
    except Exception as e:
        print("[NVD ERROR]", e)
        return []

    cve_list = []
    for item in js.get("vulnerabilities", []):
        meta = item.get("cve", {})
        cve_id = meta.get("id")
        desc = meta.get("descriptions", [{}])[0].get("value", "")
        published = meta.get("published", "Unknown")

        metrics = meta.get("metrics", {})
        cvss = None
        if "cvssMetricV31" in metrics:
            cvss = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV30" in metrics:
            cvss = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV2" in metrics:
            cvss = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
        else:
            cvss = 0.0

        cve_list.append({
            "id": cve_id,
            "description": desc,
            "published": published,
            "cvss": float(cvss),
            "sources": ["NVD"],
            "trend_score": 0
        })

    return cve_list


# -------------------------------------------
# Merge Trending Sources
# -------------------------------------------
def merge_trending():
    print("Collecting feeds...")

    nvd = fetch_nvd()
    bc = fetch_bleepingcomputer()
    hn = fetch_hackernews()
    reddit_netsec = fetch_reddit("netsec")
    reddit_cyber = fetch_reddit("cybersecurity")

    source_map = {
        "BleepingComputer": bc,
        "TheHackerNews": hn,
        "RedditNetsec": reddit_netsec,
        "RedditCyber": reddit_cyber
    }

    # Build index for fast lookup
    trending = []

    for cve in nvd:
        score = 0
        src_tags = ["NVD"]

        for src_name, cve_list in source_map.items():
            if cve["id"] in cve_list:
                score += 1
                src_tags.append(src_name)

        # Bonus: high severity emphasized
        if cve["cvss"] >= 9.0:
            score += 1

        cve["trend_score"] = score
        cve["sources"] = src_tags

        if score > 0:
            trending.append(cve)

    # Sort: trending_score → CVSS → publish date
    trending.sort(key=lambda x: (x["trend_score"], x["cvss"]), reverse=True)

    return trending


# -------------------------------------------
# Save JSON File
# -------------------------------------------
def save_json(data):
    os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=2)


# -------------------------------------------
# Main Entry
# -------------------------------------------
if __name__ == "__main__":
    print("=== CVEPulse Trending Builder ===")
    trending = merge_trending()

    output = {
        "last_updated": datetime.utcnow().isoformat() + "Z",
        "count": len(trending),
        "cves": trending
    }

    save_json(output)

    print(f"✓ Trending CVEs saved → {DATA_FILE}")
    print(f"✓ Total trending: {len(trending)}")
