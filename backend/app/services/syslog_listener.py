"""
ThreatIQ — Async Syslog UDP Listener (RFC 5424, Phase 1 / Task T1.1)

Binds a UDP socket on SYSLOG_UDP_HOST:SYSLOG_UDP_PORT (default 127.0.0.1:5514),
receives datagrams, delegates parsing to syslog_parser, and persists valid events
through EventPipelineService.

Lifecycle:
  - start_syslog_listener()  → creates the asyncio transport and returns a stop handle.
  - stop_syslog_listener()   → closes the transport and cancels the background task.

This module is I/O-only: all parsing logic lives in syslog_parser.py.
"""

from __future__ import annotations

import asyncio
from typing import Optional

from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.db.session import SessionLocal
from backend.app.services.event_pipeline import EventPipelineService
from backend.app.services.syslog_parser import (
    SyslogParseError,
    parse_rfc5424,
    to_security_event,
)

# Module-level handle so main.py lifespan can stop the listener cleanly.
_transport: Optional[asyncio.DatagramTransport] = None
_listener_task: Optional[asyncio.Task] = None  # type: ignore[type-arg]


# ---------------------------------------------------------------------------
# asyncio DatagramProtocol implementation
# ---------------------------------------------------------------------------

class _SyslogUDPProtocol(asyncio.DatagramProtocol):
    """
    asyncio DatagramProtocol that receives UDP datagrams and feeds the pipeline.

    One instance is created per listener lifetime.  datagram_received() is
    called by the event loop on the main thread — it must not block.
    """

    def __init__(self, source_ip_override: Optional[str] = None) -> None:
        self._source_ip_override = source_ip_override
        super().__init__()

    def connection_made(self, transport: asyncio.BaseTransport) -> None:  # type: ignore[override]
        sock = transport.get_extra_info("sockname")
        logger.info(
            f"[syslog] UDP listener ready on {sock[0]}:{sock[1]}"
        )

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        """Called by the event loop for every incoming UDP datagram."""
        sender_ip, sender_port = addr
        try:
            msg = parse_rfc5424(data)
        except SyslogParseError as exc:
            logger.warning(
                f"[syslog] Malformed datagram from {sender_ip}:{sender_port} — {exc}"
            )
            return

        event_in = to_security_event(msg)
        # Inject the actual UDP sender address as source_ip
        event_in = event_in.model_copy(update={"source_ip": self._source_ip_override or sender_ip})

        # Persist via EventPipelineService in a threadpool executor so we
        # never block the event loop with synchronous SQLAlchemy calls.
        loop = asyncio.get_event_loop()
        loop.run_in_executor(None, _persist_event, event_in)

    def error_received(self, exc: Exception) -> None:
        logger.error(f"[syslog] UDP error: {exc}")

    def connection_lost(self, exc: Optional[Exception]) -> None:
        if exc:
            logger.warning(f"[syslog] Connection lost: {exc}")
        else:
            logger.info("[syslog] UDP listener closed cleanly.")


# ---------------------------------------------------------------------------
# Database persistence helper (runs in threadpool)
# ---------------------------------------------------------------------------

def _persist_event(event_in) -> None:  # type: ignore[no-untyped-def]
    """Synchronous helper: open a session, persist the event, close."""
    db = SessionLocal()
    try:
        db_event, latency_ms = EventPipelineService.ingest_event(db, event_in)
        logger.info(
            f"[syslog] Persisted event {db_event.event_id} "
            f"({db_event.event_type}) in {latency_ms}ms"
        )
    except Exception as exc:
        logger.error(f"[syslog] Failed to persist syslog event: {exc}")
        db.rollback()
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Public lifecycle API
# ---------------------------------------------------------------------------

async def start_syslog_listener() -> None:
    """
    Starts the UDP listener.  Should be called once from the FastAPI lifespan
    startup hook.

    Binds to settings.SYSLOG_UDP_HOST : settings.SYSLOG_UDP_PORT.
    """
    global _transport

    host = settings.SYSLOG_UDP_HOST
    port = settings.SYSLOG_UDP_PORT

    try:
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _SyslogUDPProtocol(),
            local_addr=(host, port),
        )
        _transport = transport
        logger.info(f"[syslog] Listener started on udp://{host}:{port}")
    except OSError as exc:
        # Non-fatal: log the error but let the rest of the application run.
        logger.error(
            f"[syslog] Could not bind UDP socket on {host}:{port} — {exc}. "
            "Syslog ingestion will be unavailable."
        )


def stop_syslog_listener() -> None:
    """
    Stops the UDP listener.  Should be called from the FastAPI lifespan
    shutdown hook.
    """
    global _transport
    if _transport is not None and not _transport.is_closing():
        _transport.close()
        logger.info("[syslog] UDP listener stopped.")
    _transport = None

