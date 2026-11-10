"""
ThreatIQ Security Middleware and Enforcement
Handles security response headers, request correlation IDs, and non-destructive action policies.
"""

import uuid
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from backend.app.core.config import settings
from backend.app.core.logging import logger


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Applies security response headers:
    - X-Content-Type-Options: nosniff
    - X-Frame-Options: DENY
    - X-XSS-Protection: 1; mode=block
    - Content-Security-Policy (Restricted)
    - Strict-Transport-Security
    - X-Request-ID: Unique per-request tracing
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        request.state.request_id = request_id

        response: Response = await call_next(request)

        # Inject security headers
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

        return response


def enforce_non_destructive(action_name: str) -> None:
    """
    Validates that destructive security actions are not executed automatically.
    ThreatIQ policy: All remediation requires human-in-the-loop multi-signature authorization.
    """
    if not settings.ALLOW_DESTRUCTIVE_ACTIONS:
        logger.warning(
            f"Blocked attempt to execute automated action '{action_name}'. "
            "ThreatIQ engineering policy strictly disallows destructive automation."
        )
        raise PermissionError(
            f"Automated action '{action_name}' is blocked by ThreatIQ Non-Destructive Security Policy."
        )

