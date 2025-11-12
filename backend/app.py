"""
CVEPulse Backend API
Serves trending CVE data and refreshes it automatically every 15 minutes.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import os
import json
import asyncio
from apscheduler.schedulers.background import BackgroundScheduler
from backend.scheduler import fetch_trending_cves

app = FastAPI(title="CVEPulse API", version="1.0")

# Allow frontend to access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------
# File path setup
# ---------------------------------------------------------------------
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
os.makedirs(DATA_DIR, exist_ok=True)
DATA_PATH = os.path.join(DATA_DIR, "trending_cves.json")

# ---------------------------------------------------------------------
# Background job to refresh every 15 minutes
# ---------------------------------------------------------------------
scheduler = BackgroundScheduler()

def scheduled_job():
    """Runs periodically every 15 min."""
    try:
        print("[Scheduler] Refreshing CVE data ...")
        asyncio.run(fetch_trending_cves(DATA_PATH))
        print("[Scheduler] Done ✓")
    except Exception as e:
        print(f"[Scheduler Error] {e}")

# Add recurring job
scheduler.add_job(scheduled_job, "interval", minutes=15)
scheduler.start()

# ---------------------------------------------------------------------
# API Routes
# ---------------------------------------------------------------------
@app.get("/")
def root():
    return {"status": "CVEPulse API is running", "source": "Render"}

@app.get("/api/trending")
def get_trending():
    """Return the current trending CVE data."""
    if os.path.exists(DATA_PATH):
        with open(DATA_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data
    else:
        return {"error": "No trending data yet — please wait for the first scheduler run."}

# ---------------------------------------------------------------------
# Manual refresh trigger
# ---------------------------------------------------------------------
@app.get("/api/refresh")
async def manual_refresh():
    """Force a refresh (manual trigger)."""
    await fetch_trending_cves(DATA_PATH)
    return {"status": "Manual refresh completed ✓"}

# ---------------------------------------------------------------------
# Run manually (optional for local testing)
# ---------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
