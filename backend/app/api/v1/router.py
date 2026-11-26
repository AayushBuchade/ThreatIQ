"""ThreatIQ API v1 Router Aggregator."""

from fastapi import APIRouter
from backend.app.api.v1.endpoints import email, health, system, events

api_router = APIRouter()

api_router.include_router(health.router)
api_router.include_router(system.router)
api_router.include_router(events.router)
api_router.include_router(email.router)

