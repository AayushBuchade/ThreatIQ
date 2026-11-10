"""
Database Initialization Helper
Creates tables if they do not exist (useful for testing and development boots).
"""

from backend.app.db.base import Base
from backend.app.db.session import engine
from backend.app.core.logging import logger
# Import all models to ensure registered on metadata
import backend.app.models.system_metric # noqa: F401
import backend.app.models.security_event # noqa: F401


def init_db() -> None:
    """Creates database schema if not present."""
    logger.info("Initializing ThreatIQ database schema...")
    Base.metadata.create_all(bind=engine)
    logger.info("Database schema initialized successfully.")
