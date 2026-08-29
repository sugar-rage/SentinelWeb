"""
SentinelWeb — FastAPI application entry point.

Registers all routers, middleware, CORS configuration, and ML model lifespan.
Run with:  uvicorn app.main:app --reload
"""

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.health import router as health_router
from app.routes.auth_routes import router as auth_router
from app.routes.detection_routes import router as detection_router
from app.routes.dashboard_routes import router as dashboard_router
from app.routes.report_routes import router as report_router
from app.middleware.request_logger import log_requests
from app.ml.predictor import ml_predictor

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("sentinelweb")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager to load and warm up ML models once at server startup."""
    logger.info("Initializing SentinelWeb Security Engine...")
    success = ml_predictor.load_models()
    if success:
        logger.info("ML models loaded successfully")
        print("ML models loaded successfully")
    else:
        logger.warning("ML models unavailable — using rule-based fallback")
        print("ML models unavailable — using rule-based fallback")
    yield
    logger.info("Shutting down SentinelWeb Security Engine...")


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
    lifespan=lifespan,
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