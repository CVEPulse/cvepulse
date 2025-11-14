# backend/scheduler.py
from __future__ import annotations
import os, re, json, math
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Set
import requests
import feedparser

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
TREND_PATH = os.path.join(DATA_DIR, "trending_cves.json")

RSS_FEEDS = {
    "TheHackerNews": "https://feeds.feedburner.com/TheHackersNews",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "RedditNetsec": "https://www.reddit.com/r/netsec/.rss",
    "RedditCyber": "https://www.reddit.com/r/cybersecurity/.rss",
}

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

SRC_W = {  # source weights
    "TheHackerNews": 3.0,
    "BleepingComputer": 3.0,
    "RedditNetsec": 2.0,
    "RedditCyber": 1.6,
    "NVD": 1.0,
}

def utcnow() -> datetime:
    return datetime.now(timezone.utc)

def to_aware_utc(dt_like) -> datetime:
    """Accept datetime or ISO string, return tz-aware UTC datetime."""
    if isinstance(dt_like, datetime):
        if dt_like.tzinfo is None:
            return dt_like.replace(tzinfo=timezone.utc)
        return dt_like.astimezone(timezone.utc)
    if isinstance(dt_like, str) and dt_like:
        try:
            return datetime.fromisoformat(dt_like.replace("Z", "+00:00")).astimezone(timezone.utc)
        except Exception:
            return utcnow()
    return utcnow()

def recency_decay(dt_like, half_life_days: float = 3.0) -> float:
    dt = to_aware_utc(dt_like)
    age_days = max(0.0, (utcnow() - dt).total_seconds() / 86400.0)
    return 1.0 if half_life_days <= 0 else 0.5 ** (age_days / half_life_days)

def fetch_kev_set() -> Set[str]:
    try:
        r = requests.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            timeout=20,
        )
        r.raise_for_status()
        data = r.json()
        return {i.get("cveID", "").upper() for i in data.get("vulnerabilities", []) if i.get("cveID")}
    except Exception:
        return set()

def collect_mentions(window_days: int = 7) -> Dict[str, Dict]:
    mentions: Dict[str, Dict] = {}
    cut = utcnow() - timedelta(days=window_days)

    for src, url in RSS_FEEDS.items():
        try:
            feed = feedparser.parse(url)
            for e in feed.entries:
                text = " ".join(str(x) for x in [e.get("title",""), e.get("summary","")])
                for m in CVE_RE.findall(text):
                    cve = m.upper()
                    rec = mentions.setdefault(cve, {"sources": set(), "first_seen": utcnow()})
                    rec["sources"].add(src)

                    # feedparser *_parsed is a struct_time (naive) → make aware UTC
                    tp = e.get("published_parsed") or e.get("updated_parsed")
                    if tp:
                        seen = datetime(*tp[:6], tzinfo=timezone.utc)
                    else:
                        seen = utcnow()
                    if seen < rec["first_seen"]:
                        rec["first_seen"] = seen
        except Exception:
            continue

    # keep only within window
    pruned = {}
    for cve, rec in mentions.items():
        if rec["first_seen"] >= cut:
            pruned[cve] = {"sources": sorted(rec["sources"]), "first_seen": to_aware_utc(rec["first_seen"])}
    return pruned

def fetch_nvd(window_days: int = 7) -> Dict[str, Dict]:
    start = (utcnow() - timedelta(days=window_days)).strftime("%Y-%m-%dT%H:%M:%S.000")
    end   = utcnow().strftime("%Y-%m-%dT%H:%M:%S.000")
    params_primary  = {"resultsPerPage": 200, "pubStartDate": start,    "pubEndDate": end}
    params_fallback = {"resultsPerPage": 200, "lastModStartDate": start, "lastModEndDate": end}
    base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"apiKey": os.getenv("NVD_API_KEY")} if os.getenv("NVD_API_KEY") else {}

    def call(p):
        r = requests.get(base, params=p, headers=headers, timeout=40)
        r.raise_for_status()
        return r.json()

    out: Dict[str, Dict] = {}
    try:
        data = call(params_primary)
    except Exception:
        data = call(params_fallback)

    for item in data.get("vulnerabilities", []):
        c = item.get("cve", {})
        cve_id = (c.get("id") or "").upper()
        if not cve_id:
            continue

        # description
        desc = ""
        for d in c.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", ""); break

        # cvss (prefer v3.1/v3.0)
        cvss = 0.0
        metrics = c.get("metrics", {})
        for key in ("cvssMetricV31","cvssMetricV30","cvssMetricV2"):
            if key in metrics and metrics[key]:
                try:
                    cvss = float(metrics[key][0]["cvssData"]["baseScore"])
                    break
                except Exception:
                    pass

        pub_raw = c.get("published") or c.get("lastModified") or ""
        pub_dt = to_aware_utc(pub_raw)

        out[cve_id] = {
            "id": cve_id,
            "description": desc,
            "cvss": cvss,
            "published": pub_dt,
            "sources": {"NVD"},
        }
    return out

def build_trending(window_days: int = 7, top_limit: int = 75) -> List[Dict]:
    kev = fetch_kev_set()
    mentions = collect_mentions(window_days=window_days)
    nvd = fetch_nvd(window_days=window_days)

    all_ids = set(nvd.keys()) | set(mentions.keys())
    merged: List[Dict] = []

    for cve in all_ids:
        n = nvd.get(cve)
        m = mentions.get(cve)

        if n and m:
            sources = set(n["sources"]) | set(m["sources"])
            published = to_aware_utc(n["published"])
            cvss = float(n["cvss"] or 0.0)
            desc = n["description"]
            first_seen = to_aware_utc(m["first_seen"])
        elif n:
            sources = set(n["sources"])
            published = to_aware_utc(n["published"])
            cvss = float(n["cvss"] or 0.0)
            desc = n["description"]
            first_seen = published
        else:
            sources = set(m["sources"])
            published = None
            cvss = 0.0
            desc = "(Mentioned in news/social sources)"
            first_seen = to_aware_utc(m["first_seen"])

        # trending score
        mention_score = sum(SRC_W.get(s,1.0) for s in sources if s != "NVD")
        rec_dt = published or first_seen
        rec_score = 2.0 * recency_decay(rec_dt, half_life_days=3.0)
        cvss_boost = 0.6 * (cvss / 10.0)
        kev_bonus = 2.0 if cve in kev else 0.0
        score = mention_score + rec_score + cvss_boost + kev_bonus

        merged.append({
            "id": cve,
            "description": desc,
            "cvss": round(cvss,1),
            "published": (to_aware_utc(published).isoformat() if published else "Unknown"),
            "sources": sorted(sources),
            "trend_score": round(score, 3),
            "kev": cve in kev,
        })

    # strict “top” filter
    def is_top(x):
        if x["kev"]:
            return True
        if x["trend_score"] >= 3.0:
            return True
        if x["cvss"] >= 8.8 and x["trend_score"] >= 2.0:
            return True
        return False

    top = [x for x in merged if is_top(x)]
    top.sort(key=lambda r: (r["trend_score"], r["cvss"]), reverse=True)
    return top[:top_limit]

def run_once():
    results = build_trending(window_days=7, top_limit=75)
    os.makedirs(DATA_DIR, exist_ok=True)
    payload = {
        "last_updated": utcnow().isoformat(),
        "count": len(results),
        "cves": results,
    }
    with open(TREND_PATH, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False)
    print(f"✓ Trending CVEs saved → {TREND_PATH}")
    print(f"✓ Total trending: {len(results)}")

if __name__ == "__main__":
    run_once()
