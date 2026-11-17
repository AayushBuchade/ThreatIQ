"""
ThreatIQ — Async Syslog Listeners (RFC 5424, Phase 1 / Task T1.1)

UDP binds SYSLOG_UDP_HOST:SYSLOG_UDP_PORT (default 127.0.0.1:5514).
TCP binds SYSLOG_TCP_HOST:SYSLOG_TCP_PORT (default 127.0.0.1:5515) and
accepts only RFC 6587 octet-counted frames.

Both transports delegate message parsing to syslog_parser and persist valid
events through EventPipelineService.

Lifecycle:
  - start_syslog_listener() / stop_syslog_listener()
  - start_syslog_tcp_listener() / stop_syslog_tcp_listener()

This module is I/O-only: all RFC 5424 parsing lives in syslog_parser.py.
"""

from __future__ import annotations

import asyncio
import threading
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

# Module-level handles so main.py lifespan can stop the listeners cleanly.
_transport: Optional[asyncio.DatagramTransport] = None
_listener_task: Optional[asyncio.Task] = None  # type: ignore[type-arg]
_tcp_server: Optional[asyncio.Server] = None
_tcp_client_tasks: set[asyncio.Task] = set()  # type: ignore[type-arg]

# RFC 6587 length tokens are ASCII digits. Cap the token so a peer cannot
# stream digits forever, and never buffer more than one UDP-sized payload.
_MAX_OCTET_LENGTH_DIGITS = 10
_HARD_MAX_FRAME_BYTES = 65_535


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

# One syslog write at a time. Concurrent sessions on the shared SQLite
# connection used in tests (and the default local SQLite file) can roll
# back each other's commit. UDP still persists the same way, just serialized.
_persist_lock = threading.Lock()


def _persist_event(event_in) -> None:  # type: ignore[no-untyped-def]
    """Synchronous helper: open a session, persist the event, close."""
    with _persist_lock:
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


# ---------------------------------------------------------------------------
# RFC 6587 octet-counted TCP framing
# ---------------------------------------------------------------------------

class _OctetFrameError(Exception):
    """The TCP byte stream cannot be split into a safe octet-counted frame."""


def _max_tcp_frame_bytes() -> int:
    """Configured frame cap, always within 1..65535."""
    try:
        configured = int(settings.SYSLOG_TCP_MAX_FRAME_BYTES)
    except (TypeError, ValueError):
        configured = _HARD_MAX_FRAME_BYTES
    if configured < 1:
        return 1
    return min(configured, _HARD_MAX_FRAME_BYTES)


def _pop_octet_frame(buffer: bytearray, max_frame: int) -> Optional[bytes]:
    """
    Remove one complete RFC 6587 octet-counted frame from ``buffer``.

    Returns the syslog message bytes, or None when more bytes are required.
    Raises _OctetFrameError when the length prefix is not a safe decimal count.
    """
    if not buffer:
        return None

    space_at = buffer.find(b" ")
    if space_at == -1:
        if not buffer.isdigit():
            raise _OctetFrameError("octet-count length prefix is not decimal")
        if len(buffer) > _MAX_OCTET_LENGTH_DIGITS:
            raise _OctetFrameError("octet-count length prefix too long")
        return None

    length_token = bytes(buffer[:space_at])
    if (
        not length_token
        or not length_token.isdigit()
        or len(length_token) > _MAX_OCTET_LENGTH_DIGITS
    ):
        raise _OctetFrameError("octet-count length prefix is not a safe decimal")

    msg_len = int(length_token)
    if msg_len < 1 or msg_len > max_frame:
        raise _OctetFrameError(
            f"octet-count length {msg_len} outside 1..{max_frame}"
        )

    frame_end = space_at + 1 + msg_len
    if len(buffer) < frame_end:
        return None

    frame = bytes(buffer[space_at + 1:frame_end])
    del buffer[:frame_end]
    return frame


def _ingest_tcp_frame(frame: bytes, sender_ip: str, sender_port: int) -> None:
    """Parse one framed RFC 5424 message and persist it off the event loop."""
    try:
        msg = parse_rfc5424(frame)
    except SyslogParseError as exc:
        logger.warning(
            f"[syslog] Malformed TCP message from {sender_ip}:{sender_port} — {exc}"
        )
        return

    event_in = to_security_event(msg).model_copy(update={"source_ip": sender_ip})
    loop = asyncio.get_running_loop()
    loop.run_in_executor(None, _persist_event, event_in)


async def _handle_tcp_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    """Read octet-counted frames from one TCP client until EOF or a bad frame."""
    peer = writer.get_extra_info("peername") or ("unknown", 0)
    sender_ip = str(peer[0]) if isinstance(peer, tuple) else "unknown"
    sender_port = int(peer[1]) if isinstance(peer, tuple) and len(peer) > 1 else 0
    buffer = bytearray()
    max_frame = _max_tcp_frame_bytes()

    try:
        while True:
            chunk = await reader.read(4096)
            if not chunk:
                if buffer:
                    logger.warning(
                        f"[syslog] TCP connection from {sender_ip}:{sender_port} "
                        "closed with an incomplete frame"
                    )
                break
            buffer.extend(chunk)
            try:
                while True:
                    frame = _pop_octet_frame(buffer, max_frame)
                    if frame is None:
                        break
                    _ingest_tcp_frame(frame, sender_ip, sender_port)
            except _OctetFrameError as exc:
                logger.warning(
                    f"[syslog] Malformed TCP frame from {sender_ip}:{sender_port} — {exc}"
                )
                break
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.error(f"[syslog] TCP client error from {sender_ip}:{sender_port}: {exc}")
    finally:
        if not writer.is_closing():
            writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def _accept_tcp_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    """Track the handler task so shutdown can cancel a blocked read."""
    task = asyncio.current_task()
    if task is not None:
        _tcp_client_tasks.add(task)
        task.add_done_callback(_tcp_client_tasks.discard)
    await _handle_tcp_client(reader, writer)


async def start_syslog_tcp_listener() -> None:
    """
    Start the RFC 6587 TCP listener.

    Bind failures are logged and do not stop the rest of the application.
    """
    global _tcp_server

    host = settings.SYSLOG_TCP_HOST
    port = settings.SYSLOG_TCP_PORT

    try:
        _tcp_server = await asyncio.start_server(
            _accept_tcp_client,
            host=host,
            port=port,
        )
        bound = [sock.getsockname() for sock in (_tcp_server.sockets or [])]
        logger.info(f"[syslog] Listener started on tcp://{host}:{port} bound={bound}")
    except OSError as exc:
        _tcp_server = None
        logger.error(
            f"[syslog] Could not bind TCP socket on {host}:{port} — {exc}. "
            "TCP syslog ingestion will be unavailable."
        )


async def stop_syslog_tcp_listener() -> None:
    """Stop accepting TCP syslog clients and cancel in-flight reads."""
    global _tcp_server

    server = _tcp_server
    _tcp_server = None
    if server is not None:
        server.close()

    tasks = [task for task in list(_tcp_client_tasks) if not task.done()]
    for task in tasks:
        task.cancel()
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)

    if server is not None:
        await server.wait_closed()
        logger.info("[syslog] TCP listener stopped.")

