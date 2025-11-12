# backend/utils/kev.py
from __future__ import annotations
import json
import datetime
from pathlib import Path
from typing import Dict, Set, Tuple, Optional

import requests

# Official CISA KEV JSON feed (stable path)
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Store a local cache so you aren’t blocked if the feed is temporarily down
DATA_DIR = Path(__file__).resolve().parent.parent / "data"
CACHE_FILE = DATA_DIR / "kev_cache.json"
DATA_DIR.mkdir(exist_ok=True)


def fetch_kev() -> Dict:
    """Fetch KEV catalog from CISA; returns parsed JSON dict."""
    resp = requests.get(KEV_URL, timeout=30)
    resp.raise_for_status()
    return resp.json()


def load_kev_cache() -> Dict:
    """Load local KEV cache file if present, else {}."""
    if CACHE_FILE.exists():
        try:
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_kev_cache(payload: Dict) -> None:
    payload = {
        "fetched_at": datetime.datetime.now(datetime.UTC).isoformat(),
        "data": payload,
    }
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def load_kev_set() -> Tuple[Set[str], Optional[Dict]]:
    """
    Returns (set_of_cve_ids, raw_catalog_dict or None).
    Will try live fetch, then fall back to local cache.
    """
    try:
        live = fetch_kev()
        save_kev_cache(live)
        catalog = live
    except Exception:
        cache = load_kev_cache()
        catalog = cache.get("data")

    cve_set: Set[str] = set()
    if catalog:
        # CISA format uses "vulnerabilities": [ {"cveID": "CVE-2025-XXXX", ...}, ...]
        vulns = catalog.get("vulnerabilities", [])
        for v in vulns:
            cve = v.get("cveID")
            if cve:
                cve_set.add(cve.strip())
    return cve_set, catalog


def is_in_kev(cve_id: str, kev_set: Set[str]) -> bool:
    return (cve_id or "").strip() in kev_set
