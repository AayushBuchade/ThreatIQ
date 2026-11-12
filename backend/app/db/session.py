"""
ThreatIQ Database Engine and Session Factory
Configures SQLAlchemy session pooling for FastAPI endpoints and health verification.
"""

import time
from typing import Generator, Dict, Any
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from backend.app.core.config import settings
from backend.app.core.logging import logger

is_sqlite = "sqlite" in settings.SYNC_DATABASE_URL

connect_args = {"check_same_thread": False} if is_sqlite else {}
engine_kwargs: Dict[str, Any] = {
    "connect_args": connect_args,
    "echo": False,
    "future": True,
}

if not is_sqlite:
    engine_kwargs.update({
        "pool_size": 20,
        "max_overflow": 10,
        "pool_pre_ping": True,
    })

engine = create_engine(
    settings.SYNC_DATABASE_URL,
    **engine_kwargs
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    expire_on_commit=False
)


def get_db() -> Generator[Session, None, None]:
    """Dependency that yields a database session per request."""
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def check_db_connection() -> Dict[str, Any]:
    """
    Executes a SELECT 1 query to verify database connectivity.
    Returns status string and measured ping latency in milliseconds.
    """
    start_time = time.perf_counter()
    try:
        with SessionLocal() as session:
            result = session.execute(text("SELECT 1"))
            scalar = result.scalar()
            latency = (time.perf_counter() - start_time) * 1000.0
            if scalar == 1:
                return {
                    "status": "connected",
                    "latency_ms": round(latency, 2),
                    "error": None
                }
            return {
                "status": "degraded",
                "latency_ms": round(latency, 2),
                "error": "Unexpected scalar result"
            }
    except Exception as e:
        latency = (time.perf_counter() - start_time) * 1000.0
        logger.error(f"Database healthcheck failed: {e}")
        return {
            "status": "disconnected",
            "latency_ms": round(latency, 2),
            "error": str(e)
        }
