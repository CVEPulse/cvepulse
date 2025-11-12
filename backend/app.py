from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from apscheduler.schedulers.background import BackgroundScheduler
import os
import json
from datetime import datetime
from backend.scheduler import fetch_trending_cves  # ✅ fixed import for Render

app = FastAPI(title="CVEPulse API", version="2.0")

# Allow frontend access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATA_FILE = os.path.join(os.path.dirname(__file__), "data", "trending_cves.json")

# =========================================================
# === Background Refresh Job (every 15 minutes) ===========
# =========================================================
def scheduled_refresh():
    """Refresh CVE data every 15 minutes automatically."""
    try:
        print(f"[{datetime.utcnow().isoformat()}] 🔄 Refreshing CVE data...")
        cves = fetch_trending_cves()
        if cves and len(cves) > 0:
            with open(DATA_FILE, "w", encoding="utf-8") as f:
                json.dump(cves, f, indent=2)
            print(f"[✓] Saved {len(cves)} CVEs → {DATA_FILE}")
        else:
            print("[!] No new CVE data received.")
    except Exception as e:
        print(f"[⚠] Scheduled refresh failed: {e}")

scheduler = BackgroundScheduler()
scheduler.add_job(scheduled_refresh, "interval", minutes=15)
scheduler.start()

# =========================================================
# === API Endpoints =======================================
# =========================================================

@app.get("/api/trending")
def get_trending():
    """Return latest trending CVEs (used by frontend)."""
    try:
        if not os.path.exists(DATA_FILE):
            return JSONResponse(content={"error": "No data found"}, status_code=404)

        with open(DATA_FILE, "r", encoding="utf-8") as f:
            cves = json.load(f)

        return {"count": len(cves), "last_updated": datetime.utcnow().isoformat(), "cves": cves}
    except Exception as e:
        return JSONResponse(content={"error": f"Failed to load CVE data: {e}"}, status_code=500)


@app.get("/")
def root():
    """Root health check for Render."""
    return {
        "service": "CVEPulse API",
        "status": "online",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }

# =========================================================
# === Shutdown Handling ===================================
# =========================================================

@app.on_event("shutdown")
def shutdown_event():
    scheduler.shutdown(wait=False)
