# backend/app.py
import json
import os
from pathlib import Path
from typing import Any, Dict

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime, timezone

# ---------- Settings / Paths ----------
ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
TREND_FILE = DATA_DIR / "trending_cves.json"

ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "").strip()
NVD_API_KEY = os.getenv("NVD_API_KEY", "").strip()
NEWS_SOURCES = os.getenv("NEWS_SOURCES", "").strip()
TZ = os.getenv("TZ", "UTC").strip()

def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

# ---------- App ----------
app = FastAPI(title="CVEPulse API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # hostinger/localhost/anything
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# in-memory cache
_cache: Dict[str, Any] = {"last_updated": None, "count": 0, "cves": []}

# ---------- Helpers ----------
def _empty_payload() -> Dict[str, Any]:
    return {"last_updated": utcnow_iso(), "count": 0, "cves": []}

def _load_from_disk() -> Dict[str, Any]:
    if TREND_FILE.exists():
        try:
            return json.loads(TREND_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return _empty_payload()

def _save_to_disk(payload: Dict[str, Any]) -> None:
    TREND_FILE.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

def _warm_cache_from_disk() -> None:
    global _cache
    payload = _load_from_disk()
    _cache = payload

# warm once on startup
_warm_cache_from_disk()

# ---------- Models ----------
class RefreshResponse(BaseModel):
    last_updated: str
    count: int

# ---------- Routes ----------
@app.get("/health")
def health():
    return {
        "ok": True,
        "last_updated": _cache.get("last_updated"),
        "count": _cache.get("count", 0),
        "tz": TZ,
        "has_admin": bool(ADMIN_TOKEN),
    }

@app.get("/api/trending")
def api_trending():
    """
    Public endpoint used by the frontend.
    Always returns whatever is in the cache (or disk fallback).
    """
    # If cache is empty (first cold start), reload from disk
    if not _cache.get("last_updated"):
        _warm_cache_from_disk()
    return _cache

@app.get("/admin/refresh", response_model=RefreshResponse)
@app.post("/admin/refresh", response_model=RefreshResponse)
def admin_refresh(token: str = Query(..., description="ADMIN_TOKEN value")):
    """
    Admin endpoint to rebuild the trending list.
    Accepts GET or POST: /admin/refresh?token=YOUR_TOKEN
    """
    if not ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="ADMIN_TOKEN not configured on server")
    if token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid token")

    # Lazy import to avoid import errors during build
    try:
        from backend.scheduler import build_trending
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scheduler import failed: {e}")

    try:
        # Build the trending set; you can tweak window/top_limit here
        results = build_trending(window_days=7, top_limit=100)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Trending build failed: {e}")

    # Shape it
    payload = {
        "last_updated": utcnow_iso(),
        "count": len(results),
        "cves": results,
    }

    # Update cache + persist
    global _cache
    _cache = payload
    try:
        _save_to_disk(payload)
    except Exception as e:
        # Cache is still valid even if disk write fails
        raise HTTPException(status_code=500, detail=f"Saved to cache, but disk write failed: {e}")

    return RefreshResponse(last_updated=payload["last_updated"], count=payload["count"])
