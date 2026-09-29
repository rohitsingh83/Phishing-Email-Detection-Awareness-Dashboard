"""
Main FastAPI Application Entrypoint
Serves REST API endpoints and mounts the frontend dashboard for instant local execution.
"""

import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from backend.routes.analyze import router as analyze_router
from backend.routes.dashboard import router as dashboard_router
from backend.routes.history import router as history_router
from backend.database import init_db

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

# Initialize database schema
init_db()

app = FastAPI(
    title="Phishing Email Detection & Awareness Dashboard API",
    description="Defensive Cybersecurity REST API for static email, URL, and attachment threat scoring.",
    version="1.0.0"
)

# Enable CORS for cross-origin local requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(analyze_router)
app.include_router(dashboard_router)
app.include_router(history_router)

# Mount Frontend Static Assets
if os.path.exists(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")
    css_dir = os.path.join(FRONTEND_DIR, "css")
    js_dir = os.path.join(FRONTEND_DIR, "js")
    if os.path.exists(css_dir):
        app.mount("/css", StaticFiles(directory=css_dir), name="css")
    if os.path.exists(js_dir):
        app.mount("/js", StaticFiles(directory=js_dir), name="js")

    @app.get("/")
    def serve_frontend_root():
        index_file = os.path.join(FRONTEND_DIR, "index.html")
        if os.path.exists(index_file):
            return FileResponse(index_file)
        return {"status": "online", "message": "Phishing Detection API running. Frontend folder pending."}


@app.get("/api/health")
def health_check():
    return {"status": "healthy", "service": "Phishing Detection Engine", "version": "1.0.0"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app:app", host="127.0.0.1", port=8000, reload=True)
