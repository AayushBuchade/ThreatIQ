"""
System Information & Module Status Endpoints
"""

from fastapi import APIRouter
from backend.app.schemas.system import SystemStatusResponse, ModulesResponse
from backend.app.services.system_service import get_uptime_seconds, get_platform_modules
from backend.app.core.config import settings

router = APIRouter()


@router.get("/system/status", response_model=SystemStatusResponse, tags=["System"])
async def get_system_status() -> SystemStatusResponse:
    """Returns runtime telemetry, uptime, and security constraints of the platform."""
    modules = get_platform_modules()
    completed_count = sum(1 for m in modules if m.status == "Completed")

    return SystemStatusResponse(
        platform=settings.PROJECT_NAME,
        version=settings.VERSION,
        environment=settings.ENVIRONMENT,
        uptime_seconds=get_uptime_seconds(),
        debug_mode=settings.DEBUG,
        destructive_actions_allowed=settings.ALLOW_DESTRUCTIVE_ACTIONS,
        features_implemented=completed_count,
        features_total=len(modules)
    )


@router.get("/system/modules", response_model=ModulesResponse, tags=["System"])
async def get_modules() -> ModulesResponse:
    """Returns lifecycle and implementation status of all 12 platform modules."""
    modules = get_platform_modules()
    return ModulesResponse(
        total_modules=len(modules),
        modules=modules
    )

