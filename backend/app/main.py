"""
SentinelWeb — FastAPI application entry point.

Registers all routers, middleware, CORS configuration, and ML model lifespan.
Run with:  python scripts/run_server.py
"""

import logging
import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.health import router as health_router
from app.routes.auth_routes import router as auth_router
from app.routes.detection_routes import router as detection_router
from app.routes.dashboard_routes import router as dashboard_router
from app.routes.report_routes import router as report_router
from app.routes.waf_routes import router as waf_router
from app.routes.log_routes import router as log_router
from app.middleware.request_logger import log_requests
from app.ml.predictor import ml_predictor
from app.core.config import settings
from app.database.database import SessionLocal
from app.waf.forwarder import UpstreamForwarder


class ManagementCORSMiddleware(CORSMiddleware):
    """Keep management API CORS from intercepting WAF OPTIONS requests."""

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope.get("path", "").startswith("/waf/"):
            await self.app(scope, receive, send)
            return
        await super().__call__(scope, receive, send)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("sentinelweb")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager to load and warm up ML models once at server startup."""
    settings.validate_runtime_configuration()
    logger.info("Initializing SentinelWeb Security Engine...")
    success = ml_predictor.load_models()
    if success:
        logger.info("ML models loaded successfully")
        print("ML models loaded successfully")
    else:
        logger.warning("ML models unavailable — using rule-based fallback")
        print("ML models unavailable — using rule-based fallback")
    app.state.waf_forwarder = UpstreamForwarder(
        settings.WAF_UPSTREAM_URL,
        settings.WAF_UPSTREAM_TIMEOUT_SECONDS,
        max_response_bytes=settings.WAF_MAX_UPSTREAM_RESPONSE_BYTES,
    )
    app.state.waf_semaphore = asyncio.Semaphore(settings.WAF_MAX_CONCURRENT_REQUESTS)
    try:
        yield
    finally:
        await app.state.waf_forwarder.close()
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
app.state.session_factory = SessionLocal

# ────────────────────────────────────────────────────────────────
# CORS — allow common local dev origins
# ────────────────────────────────────────────────────────────────
app.add_middleware(
    ManagementCORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
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
app.include_router(waf_router)
app.include_router(log_router)


@app.get("/")
def home():
    return {"message": "SentinelWeb API Running"}
