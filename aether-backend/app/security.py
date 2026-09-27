"""Security middleware, access control, SSRF defense, and forensic audit logging for Project AETHER.

Implements:
1. Investigator authentication & authorization dependency (API key / Bearer token).
2. Defensive HTTP Security Headers (conditional HSTS on HTTPS only, X-Content-Type-Options, X-Frame-Options, CSP, Cache-Control).
3. Request payload transmission limits (2MB protection against memory DoS).
4. Sliding-window in-memory IP rate limiter with auto-eviction of expired records.
5. SSRF and private-network target sanitization (blocking RFC 1918, loopback, and cloud metadata).
6. Centralized forensic audit logger for Section 63, Bharatiya Sakshya Adhiniyam, 2023 (formerly s.65B, Indian Evidence Act, 1872) statutory compliance.
"""

from __future__ import annotations

import hmac
import ipaddress
import os
import re
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Callable, NamedTuple
from urllib.parse import urlparse

from fastapi import Depends, HTTPException, Request, Response, Security, status
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader, HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware

from app.models import AuditLog


# ---------- Security Configuration ---------- #

AETHER_API_KEY: str = os.getenv("AETHER_API_KEY", "aether-investigator-dev-key-2026")
AETHER_REQUIRE_AUTH: bool = os.getenv("AETHER_REQUIRE_AUTH", "true").lower() in ("true", "1", "yes")

MAX_PAYLOAD_BYTES: int = int(os.getenv("MAX_PAYLOAD_BYTES", str(2 * 1024 * 1024)))  # 2MB
RATE_LIMIT_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))
RATE_LIMIT_INVESTIGATE_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_INVESTIGATE_PER_MINUTE", "10"))

raw_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000")
ALLOWED_ORIGINS: list[str] = [origin.strip() for origin in raw_origins.split(",") if origin.strip()]


# ---------- Authentication & Access Control ---------- #

api_key_header_scheme = APIKeyHeader(name="X-AETHER-KEY", auto_error=False)
bearer_token_scheme = HTTPBearer(auto_error=False)


class InvestigatorPrincipal(NamedTuple):
    operator: str
    role: str
    authenticated: bool
    method: str


def verify_investigator_auth(
    request: Request,
    api_key: str | None = Security(api_key_header_scheme),
    bearer: HTTPAuthorizationCredentials | None = Security(bearer_token_scheme),
) -> InvestigatorPrincipal:
    """Validate investigator authentication token against AETHER_API_KEY.
    
    Accepts X-AETHER-KEY header or Authorization: Bearer <key>.
    Uses constant-time comparison to prevent timing side-channel attacks.
    """
    if not AETHER_REQUIRE_AUTH:
        return InvestigatorPrincipal(
            operator="ANONYMOUS_DEV_INVESTIGATOR",
            role="investigator",
            authenticated=False,
            method="dev_bypass",
        )

    token = None
    method = "none"

    if api_key:
        token = api_key.strip()
        method = "header_x_aether_key"
    elif bearer and bearer.credentials:
        token = bearer.credentials.strip()
        method = "bearer_token"
    elif "token" in request.query_params:
        token = request.query_params["token"].strip()
        method = "query_param_token"

    if not token or not hmac.compare_digest(token.encode("utf-8"), AETHER_API_KEY.encode("utf-8")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing AETHER authentication credentials. Supply 'X-AETHER-KEY' or 'Authorization: Bearer <key>'.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    client_ip = request.client.host if request.client else "unknown"
    return InvestigatorPrincipal(
        operator=f"INVESTIGATOR_{client_ip}",
        role="investigator",
        authenticated=True,
        method=method,
    )


# ---------- Security Response Headers Middleware ---------- #

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Enforce defensive security response headers on all API responses.
    
    HSTS is strictly conditional: applied only when the request was made over HTTPS.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response: Response = await call_next(request)

        # 1. Prevent MIME-type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # 2. Clickjacking mitigation
        response.headers["X-Frame-Options"] = "DENY"

        # 3. Cross-Site Scripting (XSS) defense
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # 4. Strict-Transport-Security (HSTS) - ONLY when request is actually HTTPS!
        is_https = (
            request.url.scheme == "https"
            or request.headers.get("x-forwarded-proto", "").lower() == "https"
        )
        if is_https:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        # 5. Referrer Policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # 6. Content Security Policy
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-eval' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
            "font-src 'self' https://cdnjs.cloudflare.com; "
            "connect-src 'self' http://localhost:* http://127.0.0.1:*; "
            "img-src 'self' data: https:; "
            "frame-ancestors 'none';"
        )

        # 7. Cache-Control: prevent intermediate caching of sensitive forensic case intelligence
        path = request.url.path
        if path.startswith("/api/cases") or path.startswith("/api/analysis") or path.startswith("/api/audit-logs"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            response.headers["Pragma"] = "no-cache"

        return response


# ---------- Request Payload Limit Middleware ---------- #

class PayloadLimitMiddleware(BaseHTTPMiddleware):
    """Guards against memory exhaustion and payload flood DoS attacks."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                length_int = int(content_length)
                if length_int > MAX_PAYLOAD_BYTES:
                    return JSONResponse(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        content={
                            "detail": f"Request payload exceeds the forensic transmission limit of {MAX_PAYLOAD_BYTES} bytes ({length_int} bytes received)."
                        },
                    )
            except ValueError:
                pass
        return await call_next(request)


# ---------- In-Memory IP Rate Limiter Middleware ---------- #

class RateLimitMiddleware(BaseHTTPMiddleware):
    """In-memory sliding-window rate limiter per client IP with auto-eviction."""

    # Class-level storage to permit test harness isolation reset
    general_hits: dict[str, deque[float]] = defaultdict(deque)
    heavy_hits: dict[str, deque[float]] = defaultdict(deque)
    last_cleanup: float = time.time()

    @classmethod
    def reset_limits(cls) -> None:
        """Reset in-memory hit buffers for test isolation."""
        cls.general_hits.clear()
        cls.heavy_hits.clear()
        cls.last_cleanup = time.time()

    def _cleanup_old_records(self, now: float) -> None:
        """Evict records older than 120s to prevent unbounded memory growth."""
        if now - self.last_cleanup < 60:
            return
        RateLimitMiddleware.last_cleanup = now
        cutoff = now - 120
        for hit_map in (self.general_hits, self.heavy_hits):
            stale_ips = []
            for ip, timestamps in hit_map.items():
                while timestamps and timestamps[0] < cutoff:
                    timestamps.popleft()
                if not timestamps:
                    stale_ips.append(ip)
            for ip in stale_ips:
                del hit_map[ip]

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Exempt health check and documentation endpoints from rate limiting
        path = request.url.path
        if path in ("/api/health", "/", "/docs", "/openapi.json", "/redoc"):
            return await call_next(request)

        client_ip = request.client.host if request.client else "127.0.0.1"
        now = time.time()
        window_start = now - 60.0

        self._cleanup_old_records(now)

        # 1. Check heavy forensic computation endpoints
        is_heavy = path.startswith("/api/cases/investigate") or path.startswith("/api/analysis")
        if is_heavy:
            heavy_q = self.heavy_hits[client_ip]
            while heavy_q and heavy_q[0] < window_start:
                heavy_q.popleft()
            if len(heavy_q) >= RATE_LIMIT_INVESTIGATE_PER_MINUTE:
                retry_after = int(60 - (now - heavy_q[0])) + 1
                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    headers={"Retry-After": str(max(1, retry_after))},
                    content={
                        "detail": f"Forensic engine rate limit exceeded for intensive operations ({RATE_LIMIT_INVESTIGATE_PER_MINUTE} req/min). Please throttle requests.",
                        "retry_after": max(1, retry_after),
                    },
                )
            heavy_q.append(now)

        # 2. Check general API rate limit
        gen_q = self.general_hits[client_ip]
        while gen_q and gen_q[0] < window_start:
            gen_q.popleft()
        if len(gen_q) >= RATE_LIMIT_PER_MINUTE:
            retry_after = int(60 - (now - gen_q[0])) + 1
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                headers={"Retry-After": str(max(1, retry_after))},
                content={
                    "detail": f"API rate limit exceeded ({RATE_LIMIT_PER_MINUTE} req/min). Please wait before retrying.",
                    "retry_after": max(1, retry_after),
                },
            )
        gen_q.append(now)

        return await call_next(request)


# ---------- SSRF & Target URL Defense ---------- #

DISALLOWED_HOSTNAMES = {
    "localhost",
    "loopback",
    "metadata.google.internal",
    "instance-data",
}

CLOUD_METADATA_IPS = {
    "169.254.169.254",  # AWS/GCP/Azure link-local metadata
    "100.100.100.200",  # Alibaba cloud metadata
}


def is_safe_target_url(
    target: str,
    allow_onion: bool = True,
    direct_fetch: bool = False,
) -> tuple[bool, str]:
    """Validate target URL or IP against SSRF, loopback, private RFC 1918, and metadata endpoints.
    
    If direct_fetch is True, .onion addresses are strictly blocked because darknet
    services must never be fetched over clearnet (investigator OPSEC protection).
    Returns (is_safe, error_reason).
    """
    if not target or len(target.strip()) < 3:
        return False, "Target descriptor cannot be empty"

    target_clean = target.strip().lower()

    # Prepend scheme if missing for URL parsing
    url_to_check = target_clean if "://" in target_clean else f"http://{target_clean}"
    try:
        parsed = urlparse(url_to_check)
    except Exception as e:
        return False, f"Malformed URL target: {e}"

    # Verify scheme
    if parsed.scheme not in ("http", "https"):
        return False, f"Unsupported scheme '{parsed.scheme}'. Only http:// and https:// targets are allowed."

    hostname = (parsed.hostname or "").strip()
    if not hostname:
        return False, "Target has no valid hostname or IP address."

    # Check blacklisted hostnames
    if hostname in DISALLOWED_HOSTNAMES or hostname.endswith(".local") or hostname.endswith(".internal"):
        return False, f"Target hostname '{hostname}' is a restricted internal or link-local address."

    # Onion targets
    if hostname.endswith(".onion"):
        if direct_fetch:
            return False, (
                f"Direct clearnet fetch of .onion target '{hostname}' is blocked by OPSEC guard. "
                "Tor hidden services are fetchable ONLY through the Tor SOCKS transport (get_onion_client)."
            )
        if not allow_onion:
            return False, "Onion targets are not permitted in this configuration."
        # Validate onion format (v2 is 16 chars, v3 is 56 chars alphanumeric a-z2-7)
        onion_name = hostname.rsplit(".onion", 1)[0]
        if not re.match(r"^[a-z2-7]{16,56}$", onion_name):
            return False, "Invalid Tor onion address format."
        return True, ""

    # Check if target hostname is an IP address
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_loopback:
            return False, f"Target IP '{ip}' is a loopback address (SSRF mitigation)."
        if ip.is_private:
            return False, f"Target IP '{ip}' is a private RFC 1918 internal address (SSRF mitigation)."
        if ip.is_link_local:
            return False, f"Target IP '{ip}' is a link-local address (SSRF mitigation)."
        if str(ip) in CLOUD_METADATA_IPS:
            return False, f"Target IP '{ip}' is a cloud instance metadata service."
        if ip.is_reserved or ip.is_multicast:
            return False, f"Target IP '{ip}' is reserved or multicast."
    except ValueError:
        # Not a raw IP; it's a domain name. Verify domain format
        if not re.match(r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*\.[a-z]{2,}$", hostname):
            return False, f"Target '{hostname}' is not a valid fully-qualified domain name."

    return True, ""


def is_safe_direct_fetch(target: str) -> tuple[bool, str]:
    """Validate whether target is safe for direct (non-proxy clearnet) HTTP fetch.
    
    Direct fetch of any .onion address is strictly prohibited to prevent
    investigator deanonymization and public DNS leakage.
    """
    return is_safe_target_url(target, allow_onion=False, direct_fetch=True)


def assert_safe_direct_fetch(target: str) -> None:
    """Raise ValueError if direct (non-Tor) fetch of target is not permitted."""
    safe, reason = is_safe_direct_fetch(target)
    if not safe:
        raise ValueError(f"Direct fetch blocked by OPSEC/SSRF guard: {reason}")


# ---------- Audit Logging ---------- #

def record_audit_log(
    db: Session,
    operator: str,
    action: str,
    case_id: int | None = None,
    details: dict | None = None,
) -> AuditLog:
    """Record an investigator action to the Section 63, Bharatiya Sakshya Adhiniyam, 2023 (formerly s.65B, Indian Evidence Act, 1872) forensic audit log."""
    ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    log_entry = AuditLog(
        case_id=case_id,
        timestamp=ts,
        operator=operator or "INVESTIGATOR_SYSTEM",
        action=action,
        details=details or {},
    )
    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)
    return log_entry
