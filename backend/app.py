import os
import json
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Path to the JSON file written by scheduler.py
DATA_FILE = os.path.join(os.path.dirname(__file__), "data", "trending_cves.json")

app = FastAPI(
    title="CVEPulse API",
    version="1.0.0",
    description="Backend for CVEPulse trending CVE dashboard",
)

# Allow your frontend (Hostinger) + any others to call the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # you can restrict to your domain later
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health():
    """Simple health endpoint for Render."""
    return {"status": "ok"}


@app.get("/api/trending")
def get_trending():
    """
    Serve the trending CVEs that scheduler.py wrote to data/trending_cves.json.
    If the file does not exist yet, return an empty structure.
    """
    if not os.path.exists(DATA_FILE):
        return {
            "last_updated": None,
            "count": 0,
            "cves": [],
        }

    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        # If file is corrupt for some reason, fail gracefully
        return {
            "last_updated": None,
            "count": 0,
            "cves": [],
        }

    # Normalise keys so the frontend always sees the same shape
    cves = data.get("cves", [])
    return {
        "last_updated": data.get("last_updated"),
        "count": data.get("count", len(cves)),
        "cves": cves,
    }
