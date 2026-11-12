"""
ThreatIQ System Metric Model
Persists operational metrics, heartbeat logs, and system health records.
"""

from sqlalchemy import String, Integer, Float, JSON
from sqlalchemy.orm import Mapped, mapped_column
from backend.app.db.base import Base, TimestampMixin


class SystemMetric(Base, TimestampMixin):
    __tablename__ = "system_metrics"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    component: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    metric_name: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    metric_value: Mapped[float] = mapped_column(Float, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="ok", nullable=False)
    meta_attributes: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

