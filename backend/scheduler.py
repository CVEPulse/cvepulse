import os
import re
import json
import datetime
import asyncio
from pathlib import Path

import requests
import feedparser

# === CONFIG ===
DATA_DIR = Path(__file__).resolve().parent / "data"
DATA_DIR.mkdir(exist_ok=True)
OUTPUT_FILE = DATA_DIR / "trending_cves.json"

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Optional NVD API key (set NVD_API_KEY env var on Render / locally)
NVD_API_KEY = os.getenv("NVD_API_KEY")
HEADERS = {"User-Agent": "CVEPulse/1.3"}
if NVD_API_KEY:
    HEADERS["apiKey"] = NVD_API_KEY

FEEDS = {
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "TheHackerNews": "https://feeds.feedburner.com/TheHackersNews",
    "RedditNetsec": "https://www.reddit.com/r/netsec/.rss",
    "RedditCyber": "https://www.reddit.com/r/cybersecurity/.rss",
}


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------
def extract_cve_ids(text: str):
    """Extract all CVE identifiers from text."""
    return re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)


def _fmt_nvd(dt: datetime.datetime) -> str:
    """
    NVD examples use: 2021-08-04T00:00:00.000 (no Z in examples)
    So we convert to naive and format exactly like that.
    """
    dt_naive = dt.replace(tzinfo=None)
    return dt_naive.strftime("%Y-%m-%dT%H:%M:%S.000")


# ---------------------------------------------------------------------
# NVD fetch (simplified, no orderBy)
# ---------------------------------------------------------------------
def fetch_from_nvd(days: int = 7):
    """Fetch latest CVEs from NVD (tries pub* then lastMod*)."""
    now = datetime.datetime.now(datetime.UTC)
    start = now - datetime.timedelta(days=days)

    candidate_params = [
        {
            "resultsPerPage": 100,
            "pubStartDate": _fmt_nvd(start),
            "pubEndDate": _fmt_nvd(now),
        },
        {
            "resultsPerPage": 100,
            "lastModStartDate": _fmt_nvd(start),
            "lastModEndDate": _fmt_nvd(now),
        },
    ]

    print("=== NVD FETCH ===")
    print(f"    Using apiKey: {'YES' if NVD_API_KEY else 'NO'}")

    for params in candidate_params:
        print("[+] Fetching CVEs from NVD ...")
        print(f"    Params: {params}")
        try:
            r = requests.get(NVD_API, params=params, headers=HEADERS, timeout=25)
            r.raise_for_status()
            data = r.json()
            cves: dict[str, dict] = {}
            for item in data.get("vulnerabilities", []):
                cve = item["cve"]
                metrics = cve.get("metrics", {})
                score = 0.0
                if "cvssMetricV31" in metrics:
                    score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                elif "cvssMetricV30" in metrics:
                    score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
                elif "cvssMetricV2" in metrics:
                    score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

                cves[cve["id"]] = {
                    "id": cve["id"],
                    "description": cve["descriptions"][0]["value"],
                    "published": cve["published"],
                    "cvss": float(score),
                    "sources": ["NVD"],
                    "trend_score": 0,
                }
            print(f"[✓] Retrieved {len(cves)} CVEs from NVD.")
            return cves
        except requests.HTTPError as e:
            code = e.response.status_code if e.response is not None else "?"
            print(f"[!] NVD fetch failed with {code}, trying fallback params ...")
            continue
        except Exception as e:
            print(f"[!] NVD fetch failed: {e}")
            continue

    print("[!] All NVD attempts failed — continuing with news sources only.")
    return {}


# ---------------------------------------------------------------------
# News / social feeds
# ---------------------------------------------------------------------
def collect_mentions():
    """Collect CVE mentions from BleepingComputer, TheHackerNews, Reddit."""
    mentions: dict[str, set] = {}

    for name, url in FEEDS.items():
        print(f"[+] Scanning feed: {name}")
        try:
            feed = feedparser.parse(url)
            for entry in feed.entries[:30]:
                content = (entry.title + " " + getattr(entry, "summary", ""))
                ids = extract_cve_ids(content)
                for cid in ids:
                    cid_up = cid.upper()
                    mentions.setdefault(cid_up, set()).add(name)
        except Exception as e:
            print(f"[!] Feed {name} failed: {e}")

    print(f"[✓] Mentions collected for {len(mentions)} CVEs")
    return mentions


# ---------------------------------------------------------------------
# Merge + score
# ---------------------------------------------------------------------
def merge_and_score(nvd_cves: dict, mentions: dict):
    """Merge NVD CVEs with mention data and compute trending score."""
    for cid, sources in mentions.items():
        if cid not in nvd_cves:
            nvd_cves[cid] = {
                "id": cid,
                "description": "(Mentioned in news/social sources)",
                "published": "Unknown",
                "cvss": 0.0,
                "sources": [],
                "trend_score": 0,
            }
        nvd_cves[cid]["sources"].extend(list(sources))
        nvd_cves[cid]["trend_score"] += len(sources)

    ranked = sorted(
        nvd_cves.values(),
        key=lambda x: (x["trend_score"] * 2 + x["cvss"]),
        reverse=True,
    )
    return ranked


def save_json(cves, output_path: str):
    data = {
        "last_updated": datetime.datetime.now(datetime.UTC).isoformat(),
        "count": len(cves),
        "cves": cves,
    }
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"[✓] Wrote {len(cves)} CVEs → {output_path}")


# ---------------------------------------------------------------------
# Public entrypoint used by app.py AND CLI
# ---------------------------------------------------------------------
async def fetch_trending_cves(output_path: str):
    """
    Main function used by:
      - app.py (APSheduler / /api/refresh)
      - local CLI (via run_scheduler)
    """
    print("=== CVEPulse Multi-Source Trending ===")
    nvd_cves = fetch_from_nvd()
    mentions = collect_mentions()
    merged = merge_and_score(nvd_cves, mentions)
    save_json(merged[:200], output_path)
    print("=== Done ===")


def run_scheduler():
    """Synchronous wrapper so you can run: python scheduler.py"""
    asyncio.run(fetch_trending_cves(str(OUTPUT_FILE)))


if __name__ == "__main__":
    run_scheduler()
