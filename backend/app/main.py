"""
ThreatIQ FastAPI Application Entry Point
"""

from contextlib import asynccontextmanager
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.core.security import SecurityHeadersMiddleware
from backend.app.api.v1.router import api_router
from backend.app.db.init_db import init_db
from backend.app.services.syslog_listener import start_syslog_listener, stop_syslog_listener


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan context manager for startup and shutdown routines."""
    logger.info(f"Starting {settings.PROJECT_NAME} v{settings.VERSION} [{settings.ENVIRONMENT}]")
    # Initialize database tables for local/dev
    try:
        init_db()
        logger.info("Database initialized successfully.")
    except Exception as e:
        logger.error(f"Error during database initialization: {e}")

    # Start RFC 5424 Syslog UDP listener (skipped in test environment)
    if os.environ.get("ENVIRONMENT") != "testing":
        await start_syslog_listener()

    yield

    # Shut down Syslog listener before exiting
    if os.environ.get("ENVIRONMENT") != "testing":
        stop_syslog_listener()
    logger.info(f"Shutting down {settings.PROJECT_NAME}")


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Unified AI-Powered Cybersecurity Detection & SOC Intelligence Platform",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan
)

# Apply Security Headers Middleware
app.add_middleware(SecurityHeadersMiddleware)

# Apply CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID"]
)

# Include API v1 Router
app.include_router(api_router, prefix=settings.API_V1_PREFIX)


@app.get("/", tags=["Root"])
def root():
    """Root metadata endpoint."""
    return {
        "platform": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "phase": "Phase 0 (Foundation & Architecture)",
        "docs_url": "/docs",
        "api_v1": settings.API_V1_PREFIX
    }
