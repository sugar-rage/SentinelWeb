"""
SentinelWeb — FastAPI application entry point.

Registers all routers, middleware, and CORS configuration.
Run with:  uvicorn app.main:app --reload
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.health import router as health_router
from app.routes.auth_routes import router as auth_router
from app.routes.detection_routes import router as detection_router
from app.routes.dashboard_routes import router as dashboard_router
from app.routes.report_routes import router as report_router
from app.middleware.request_logger import log_requests

# ────────────────────────────────────────────────────────────────
# App instance
# ────────────────────────────────────────────────────────────────
app = FastAPI(
    title="SentinelWeb",
    description=(
        "AI-Based Hybrid Framework for Multi-Vector Web Attack "
        "Detection, Prevention, and Adaptive Risk Analysis"
    ),
    version="1.0.0",
)

# ────────────────────────────────────────────────────────────────
# CORS — allow common local dev origins
# ────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
        "http://localhost:5174",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ────────────────────────────────────────────────────────────────
# Middleware
# ────────────────────────────────────────────────────────────────
app.middleware("http")(log_requests)

# ────────────────────────────────────────────────────────────────
# Routers
# ────────────────────────────────────────────────────────────────
app.include_router(health_router)
app.include_router(auth_router)
app.include_router(detection_router)
app.include_router(dashboard_router)
app.include_router(report_router)


@app.get("/")
def home():
    return {"message": "SentinelWeb API Running"}