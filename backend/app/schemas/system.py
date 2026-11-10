"""Pydantic Schemas for System Status & Platform Modules."""

from typing import List, Dict, Any
from pydantic import BaseModel, Field


class ModuleStatus(BaseModel):
    id: int
    name: str
    target_phase: int
    status: str = Field(..., description="Completed | In Progress | Upcoming | Blocked")
    tech_scope: str
    description: str


class ModulesResponse(BaseModel):
    total_modules: int
    modules: List[ModuleStatus]


class SystemStatusResponse(BaseModel):
    platform: str
    version: str
    environment: str
    uptime_seconds: float
    debug_mode: bool
    destructive_actions_allowed: bool
    features_implemented: int
    features_total: int

