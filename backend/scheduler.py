# backend/scheduler.py
import os, json, requests
from datetime import datetime, timedelta, UTC

from utils.news_sources import collect_all_mentions, fetch_kev_set, source_weight

DATA_DIR  = os.path.join(os.path.dirname(__file__), "data")
os.makedirs(DATA_DIR, exist_ok=True)
OUT_PATH  = os.path.join(DATA_DIR, "trending_cves.json")

HEADERS   = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"}
NVD_BASE  = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# CVEtrends-like settings
MENTION_WINDOW_DAYS = 7
HALF_LIFE_DAYS      = 2.0      # recent mentions count more
RESULTS_LIMIT       = 150      # return plenty; we'll sort by CVSS then trending

def _decay_weight(age_days: float) -> float:
    return 0.5 ** (age_days / HALF_LIFE_DAYS)

def _fetch_nvd_one(cid: str) -> dict:
    """Return {description, severity, cvss_score, published} for a CVE id."""
    try:
        r = requests.get(NVD_BASE, params={"cveId": cid}, headers=HEADERS, timeout=25)
        if not r.ok:
            return {}
        arr = r.json().get("vulnerabilities", [])
        if not arr:
            return {}
        cve = arr[0].get("cve", {})
        desc = ""
        try:
            dlist = cve.get("descriptions") or []
            if dlist:
                desc = dlist[0].get("value") or ""
        except Exception:
            pass
        severity, score = "Medium", 0.0
        metrics = cve.get("metrics") or {}
        for m in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            mm = metrics.get(m) or []
            if mm:
                cv = mm[0].get("cvssData") or {}
                severity = cv.get("baseSeverity") or severity
                try:
                    score = float(cv.get("baseScore") or 0.0)
                except Exception:
                    pass
                break
        published = cve.get("published") or cve.get("publishedDate")
        return {"description": desc, "severity": severity, "cvss_score": score, "published": published}
    except Exception:
        return {}

def _recent_nvd_fallback(window_days=7, limit=200) -> list[dict]:
    """If feeds yield nothing, pull recently modified CVEs from NVD to avoid empty lists."""
    now   = datetime.now(UTC)
    start = (now - timedelta(days=window_days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    end   = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    events = []
    try:
        params = {
            "lastModStartDate": start,
            "lastModEndDate": end,
            "resultsPerPage": 2000,
            "startIndex": 0
        }
        while True:
            r = requests.get(NVD_BASE, params=params, headers=HEADERS, timeout=30)
            if not r.ok:
                break
            payload = r.json()
            for v in payload.get("vulnerabilities", []):
                cid = (v.get("cve", {}).get("id") or "").upper()
                if not cid:
                    continue
                # fabricate a single 'nvd' mention at "now" so scoring > 0
                events.append({"cve": cid, "source": "nvd", "dt": now, "flags": set()})
                if len(events) >= limit:
                    break
            if len(events) >= limit:
                break
            total = payload.get("totalResults", 0)
            params["startIndex"] += payload.get("resultsPerPage", 2000)
            if params["startIndex"] >= total:
                break
    except Exception:
        pass
    return events

def run_scheduler():
    now = datetime.now(UTC)
    print("=== CVEPulse (CVEtrends-style) ===")

    # 1) Collect mentions from feeds in the last N days
    raw = collect_all_mentions()
    cutoff = now - timedelta(days=MENTION_WINDOW_DAYS)
    events = [e for e in raw if e.get("dt") and e["dt"] >= cutoff]
    print(f"[i] feed events (recent {MENTION_WINDOW_DAYS}d): {len(events)}")

    # Fallback to NVD window if feeds are blocked/quiet
    if not events:
        print("[!] No recent feed events; using NVD fallback…")
        events = _recent_nvd_fallback(window_days=MENTION_WINDOW_DAYS, limit=RESULTS_LIMIT)
        print(f"[i] fallback events: {len(events)}")

    # 2) Score by source + recency (decay)
    per = {}
    for e in events:
        cid = e["cve"]; src = e["source"]; dt = e["dt"]
        age_days = (now - dt).total_seconds()/86400.0
        s = source_weight(src) * _decay_weight(age_days)
        rec = per.setdefault(cid, {"id": cid, "score": 0.0, "mentions": set(), "last_seen": dt})
        rec["score"] += s
        rec["mentions"].add(src)
        if dt > rec["last_seen"]:
            rec["last_seen"] = dt

    ranked = sorted(per.values(), key=lambda x: (-x["score"], -x["last_seen"].timestamp()))
    top_ids = [r["id"] for r in ranked[:RESULTS_LIMIT]]

    # 3) Enrich with NVD (CVSS, severity, description, published)
    details = {cid: _fetch_nvd_one(cid) for cid in top_ids}

    # 4) Build results
    results = []
    for r in ranked[:RESULTS_LIMIT]:
        cid = r["id"]
        info = details.get(cid, {})
        results.append({
            "id": cid,
            "cvss_score": float(info.get("cvss_score") or 0.0),
            "severity": info.get("severity", "Medium"),
            "description": info.get("description", ""),
            "published": info.get("published"),
            "sources": ["NVD"] + sorted(list(r["mentions"])),
            "trending_score": round(r["score"], 4),
            "last_seen": r["last_seen"].isoformat()
        })

    # 5) Sort: CVSS (desc) → Trending score (desc) → Last seen (desc)
    results.sort(
        key=lambda x: (-x["cvss_score"], -x["trending_score"], -(datetime.fromisoformat(x["last_seen"]).timestamp()))
    )

    out = {"last_updated": now.isoformat(), "window_days": MENTION_WINDOW_DAYS, "results": results}
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)

    print(f"[✓] Wrote {len(results)} → {OUT_PATH}")

if __name__ == "__main__":
    run_scheduler()
