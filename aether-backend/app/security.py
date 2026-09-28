"""Security middleware, access control, SSRF defense, and forensic audit logging for Project AETHER.

Implements:
1. Multi-key RBAC investigator authentication (X-AETHER-KEY / Bearer / ?token=)
   with investigator and auditor roles, constant-time key comparison, and a
   read-only enforcement dependency.
2. Defensive HTTP Security Headers (conditional HSTS on HTTPS only, X-Content-Type-Options, X-Frame-Options, CSP, Cache-Control).
3. Request payload transmission limits (2MB protection against memory DoS).
4. Sliding-window in-memory rate limiter bucketed per API key *and* per client IP.
5. SSRF and private-network target sanitization (blocking RFC 1918, loopback, cloud
   metadata) plus an exact-hostname allowlist for outbound OSINT fetches.
6. Centralized forensic audit logger for Section 63, Bharatiya Sakshya Adhiniyam, 2023
   (formerly s.65B, Indian Evidence Act, 1872) statutory compliance.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import logging
import os
import re
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Callable, NamedTuple, Optional
from urllib.parse import urlparse

from fastapi import Depends, HTTPException, Request, Response, Security, status
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader, HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware

from app.models import AuditLog

logger = logging.getLogger("aether.security")


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
    key_id: str = "unknown"

    @property
    def can_write(self) -> bool:
        """Whether this principal may create or mutate forensic state.

        Auditors are read-only by design. They may read and export, because an
        auditor who cannot export cannot audit; they may not create cases,
        append custody entries, or confirm an export.
        """
        return self.role in WRITE_ROLES

    @property
    def can_confirm_export(self) -> bool:
        """Only an investigator may authorize a dossier export.

        The human-in-the-loop export gate is meaningless if an auditor can
        satisfy it: the point is that a named human accepted responsibility for
        releasing the dossier.
        """
        return self.role in EXPORT_CONFIRM_ROLES


class ApiKeyRecord(NamedTuple):
    key_id: str
    key: str
    role: str
    label: str


WRITE_ROLES = frozenset({"investigator"})
EXPORT_CONFIRM_ROLES = frozenset({"investigator"})
VALID_ROLES = frozenset({"investigator", "auditor"})


def _parse_key_table(raw: str) -> list[ApiKeyRecord]:
    """Parse ``"investigator:key-a,auditor:key-b"`` into key records.

    Roles are validated rather than accepted blindly: an unknown role silently
    inheriting investigator powers would be a privilege escalation from a typo.
    Keys are compared in constant time at request time, never here.
    """
    records: list[ApiKeyRecord] = []
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        role, separator, key = entry.partition(":")
        role = role.strip().lower()
        key = key.strip()
        if not separator or not key:
            logger.warning("Ignoring malformed AETHER_API_KEYS entry (expected 'role:key').")
            continue
        if role not in VALID_ROLES:
            logger.warning(
                "Ignoring AETHER_API_KEYS entry with unknown role %r (valid: %s).",
                role, ", ".join(sorted(VALID_ROLES)),
            )
            continue
        records.append(ApiKeyRecord(
            key_id=f"{role}:{hashlib.sha256(key.encode('utf-8')).hexdigest()[:8]}",
            key=key,
            role=role,
            label=role,
        ))
    return records


def load_api_keys() -> list[ApiKeyRecord]:
    """Resolve the active key table.

    Precedence: ``AETHER_API_KEYS`` when set, otherwise the legacy single
    ``AETHER_API_KEY``, which maps to the ``investigator`` role. A single shared
    key stays fully backwards compatible; splitting roles out is opt-in.
    """
    raw_table = os.getenv("AETHER_API_KEYS", "").strip()
    if raw_table:
        records = _parse_key_table(raw_table)
        if records:
            return records
        logger.warning("AETHER_API_KEYS was set but no valid entries parsed; falling back to AETHER_API_KEY.")

    # Read the env var rather than the import-time constant so a reloaded config
    # (or a test) sees the current value instead of whatever was set at boot.
    legacy_key = os.getenv("AETHER_API_KEY", AETHER_API_KEY)
    return [
        ApiKeyRecord(
            key_id="investigator:legacy",
            key=legacy_key,
            role="investigator",
            label="legacy-single-key",
        )
    ]


API_KEYS: list[ApiKeyRecord] = load_api_keys()
LEGACY_API_KEY: str = AETHER_API_KEY


def _match_key(token: str) -> Optional[ApiKeyRecord]:
    """Constant-time lookup of a presented token against every configured key.

    Every candidate is compared even after a match, so the response time does
    not reveal which position matched or how many keys are configured.
    """
    matched: Optional[ApiKeyRecord] = None
    for record in API_KEYS:
        if hmac.compare_digest(token.encode("utf-8"), record.key.encode("utf-8")):
            matched = record
    return matched


def verify_investigator_auth(
    request: Request,
    api_key: str | None = Security(api_key_header_scheme),
    bearer: HTTPAuthorizationCredentials | None = Security(bearer_token_scheme),
) -> InvestigatorPrincipal:
    """Validate investigator authentication and resolve the caller's role.

    Accepts X-AETHER-KEY header, Authorization: Bearer <key>, or ?token=<key>
    (the last exists only for EventSource, which cannot set headers).
    Comparison is constant-time.
    """
    if not AETHER_REQUIRE_AUTH:
        return InvestigatorPrincipal(
            operator="ANONYMOUS_DEV_INVESTIGATOR",
            role="investigator",
            authenticated=False,
            method="dev_bypass",
            key_id="dev_bypass",
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

    record = _match_key(token) if token else None
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing AETHER authentication credentials. Supply 'X-AETHER-KEY' or 'Authorization: Bearer <key>'.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    client_ip = request.client.host if request.client else "unknown"
    return InvestigatorPrincipal(
        operator=f"{record.role.upper()}_{client_ip}",
        role=record.role,
        authenticated=True,
        method=method,
        key_id=record.key_id,
    )


def require_write_access(
    principal: InvestigatorPrincipal = Depends(verify_investigator_auth),
) -> InvestigatorPrincipal:
    """FastAPI dependency enforcing investigator (write) role.

    Raises 403, not 401: the caller is authenticated, they are simply not
    permitted to mutate. Returning 401 would send a legitimate client hunting
    for a credential problem that does not exist.

    The principal is pulled in via ``Depends`` rather than accepted as a plain
    argument. FastAPI analyses a dependency's own signature, and a bare
    ``InvestigatorPrincipal`` parameter is a NamedTuple, which it cannot classify
    and tries to treat as a request body.
    """
    if not principal.can_write:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Role '{principal.role}' is read-only. Custody mutation and case creation "
                "require the investigator role. Auditors may read and export."
            ),
        )
    return principal


def require_export_confirmation_role(
    principal: InvestigatorPrincipal = Depends(verify_investigator_auth),
) -> InvestigatorPrincipal:
    """FastAPI dependency restricting export affirmation to investigators.

    An auditor who can authorize their own release has not reviewed anything, so
    this is strictly narrower than :func:`require_write_access`.
    """
    if not principal.can_confirm_export:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Role '{principal.role}' cannot affirm an export. Only an investigator may "
                "release a dossier; auditors may read, verify, and export the custody ledger."
            ),
        )
    return principal


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
    """In-memory sliding-window rate limiter with auto-eviction.

    Buckets are keyed by ``(api_key_id, client_ip)`` when a key is present and
    by client IP alone otherwise. Keying on the IP alone means every investigator
    behind one NAT or egress gateway shares a single budget, so a team of ten
    cannot work: the ninth investigator is throttled because the eighth ran a
    heavy module. Keying on the credential *in addition to* the IP bounds both
    abuse from one key spraying from many hosts, and abuse from one host
    rotating many keys.
    """

    # Class-level storage to permit test harness isolation reset
    general_hits: dict[tuple[str, str], deque[float]] = defaultdict(deque)
    heavy_hits: dict[tuple[str, str], deque[float]] = defaultdict(deque)
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
            stale = []
            for bucket, timestamps in hit_map.items():
                while timestamps and timestamps[0] < cutoff:
                    timestamps.popleft()
                if not timestamps:
                    stale.append(bucket)
            for bucket in stale:
                del hit_map[bucket]

    @staticmethod
    def _bucket_key(request: Request) -> tuple[str, str]:
        """Resolve the (key_id, client_ip) bucket for a request.

        The key is read straight from the request rather than through the auth
        dependency, because this middleware runs before dependencies and must not
        depend on them. A malformed or unknown key falls back to a distinct
        ``invalid`` bucket rather than joining the anonymous one, so unauthenticated
        traffic cannot be used to exhaust the shared anonymous budget and lock out
        legitimate callers who omitted a key.
        """
        client_ip = request.client.host if request.client else "127.0.0.1"
        token = request.headers.get("X-AETHER-KEY")
        if not token:
            authorization = request.headers.get("Authorization", "")
            if authorization.lower().startswith("bearer "):
                token = authorization[7:].strip()
        if not token:
            token = request.query_params.get("token", "")

        token = (token or "").strip()
        if not token:
            return ("anonymous", client_ip)

        record = _match_key(token)
        return (record.key_id if record else "invalid-key", client_ip)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Exempt health check and documentation endpoints from rate limiting
        path = request.url.path
        if path in ("/api/health", "/", "/docs", "/openapi.json", "/redoc"):
            return await call_next(request)

        client_ip = request.client.host if request.client else "127.0.0.1"
        bucket = self._bucket_key(request)
        now = time.time()
        window_start = now - 60.0

        self._cleanup_old_records(now)

        # 1. Check heavy forensic computation endpoints
        is_heavy = path.startswith("/api/cases/investigate") or path.startswith("/api/analysis")
        if is_heavy:
            heavy_q = self.heavy_hits[bucket]
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
        gen_q = self.general_hits[bucket]
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

# Outbound OSINT sources the engine is permitted to contact. AETHER fetches are
# strictly allowlisted rather than filtered: an attribution engine that can be
# pointed at an arbitrary URL is an SSRF primitive with a legal paper trail, and
# an investigator who cannot be deanonymized by their own tooling should never
# be able to aim that tooling at internal infrastructure.
ALLOWED_EXTERNAL_INTEL_HOSTS = {
    "crt.sh",
    "www.crt.sh",
    "api.shodan.io",
    "search.censys.io",
    "api.censys.io",
}


def is_allowed_external_intel_url(target: str) -> tuple[bool, str]:
    """Validate a URL against the outbound OSINT allowlist.

    Enforces HTTPS and an exact hostname match, so a path like
    ``crt.sh/../../`` or a subdomain of an allowed host is rejected.
    """
    if not target or not target.strip():
        return False, "External intel target cannot be empty"

    url_to_check = target.strip()
    if "://" not in url_to_check:
        url_to_check = f"https://{url_to_check}"
    try:
        parsed = urlparse(url_to_check)
    except Exception as e:
        return False, f"Malformed external intel URL: {e}"

    if parsed.scheme != "https":
        return False, (
            f"External intel fetches require https, got '{parsed.scheme}'. "
            "Attribution telemetry is not collected over plaintext."
        )

    hostname = (parsed.hostname or "").strip().lower()
    if hostname not in ALLOWED_EXTERNAL_INTEL_HOSTS:
        return False, (
            f"Host '{hostname}' is not in the AETHER external intel allowlist. "
            "Add it deliberately to ALLOWED_EXTERNAL_INTEL_HOSTS if this is intended."
        )
    return True, ""


def assert_allowed_external_intel_url(target: str) -> None:
    """Raise ValueError if the URL is not an approved outbound OSINT source."""
    safe, reason = is_allowed_external_intel_url(target)
    if not safe:
        raise ValueError(f"External intel fetch blocked by allowlist: {reason}")


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
