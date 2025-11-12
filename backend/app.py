# backend/app.py
import os
import json
import asyncio
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

# Uses your existing scheduler.run_scheduler()
from scheduler import run_scheduler

app = FastAPI(title="CVEPulse")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATA_PATH = os.path.join(os.path.dirname(__file__), "data", "trending_cves.json")

@app.get("/api/trending")
def get_trending():
    if not os.path.exists(DATA_PATH):
        return {"last_updated": None, "results": []}
    with open(DATA_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

# Serve the frontend from /static
FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))
app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

@app.get("/")
def root():
    # Go to frontend
    return RedirectResponse(url="/static/index.html")

# ---------- 15-minute background refresher ----------
async def _refresh_job():
    while True:
        try:
            print("[CVEPulse] periodic refresh…")
            run_scheduler()  # rebuild data/data/trending_cves.json
        except Exception as e:
            print("[CVEPulse] refresh error:", e)
        await asyncio.sleep(15 * 60)  # 15 minutes

@app.on_event("startup")
async def _startup():
    # Prime the data once on boot so the page isn't empty
    try:
        run_scheduler()
    except Exception as e:
        print("[CVEPulse] initial refresh error:", e)
    # Start periodic refresh
    asyncio.create_task(_refresh_job())
