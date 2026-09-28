from contextlib import asynccontextmanager
import logging
import uuid

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.db import Base, engine, get_db
from app.models import AuditLog
from app.routers import analysis, cases, export, jobs
from app.routers.cases import verify_custody_chain
from app.schemas import AuditLogOut, VerifyResult
from app.services.intel import resolve_intel_mode
from app.security import (
    ALLOWED_ORIGINS,
    InvestigatorPrincipal,
    PayloadLimitMiddleware,
    RateLimitMiddleware,
    SecurityHeadersMiddleware,
    verify_investigator_auth,
)

logger = logging.getLogger("aether.api")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    logger.info("Database schema initialized.")
    yield


app = FastAPI(
    title="AETHER API",
    description="Autonomous Engine for Threat Harmonization & Entity Resolution (NTRO PS-26151). "
                "Hardened for secure evidence attribution and tamper-evident custody.",
    version="1.1.0",
    lifespan=lifespan,
)

# 1. Security Headers Middleware
app.add_middleware(SecurityHeadersMiddleware)

# 2. Payload Transmission Limit Middleware (2MB)
app.add_middleware(PayloadLimitMiddleware)

# 3. Sliding-window IP Rate Limiter Middleware
app.add_middleware(RateLimitMiddleware)

# 4. Configured CORS Origins (No Wildcard)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["Retry-After", "X-Content-Type-Options", "Content-Disposition"],
)


# ---------- Safe Error Handling (No Traceback/SQL Leaks) ---------- #

@app.exception_handler(SQLAlchemyError)
async def sqlalchemy_exception_handler(request: Request, exc: SQLAlchemyError) -> JSONResponse:
    incident_id = uuid.uuid4().hex[:12]
    logger.error("Database error [Incident %s] on %s %s: %s", incident_id, request.method, request.url.path, str(exc))
    return JSONResponse(
        status_code=500,
        content={
            "detail": "A database error occurred while processing forensic evidence.",
            "incident_id": incident_id,
        },
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    incident_id = uuid.uuid4().hex[:12]
    logger.error("Unhandled exception [Incident %s] on %s %s: %s", incident_id, request.method, request.url.path, str(exc), exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "detail": "An internal server error occurred while processing forensic request.",
            "incident_id": incident_id,
        },
    )


# ---------- Mount Routers ---------- #

app.include_router(cases.router)
app.include_router(export.router)
app.include_router(analysis.router)
app.include_router(jobs.router)


# ---------- Public & Utility Endpoints ---------- #

@app.get("/", tags=["system"])
def root() -> dict:
    return {
        "service": "AETHER Threat Attribution API",
        "status": "online",
        "version": "1.1.0",
        "docs": "/docs",
        "health": "/api/health",
        "compliance": "Section 63, Bharatiya Sakshya Adhiniyam, 2023 (formerly s.65B, Indian Evidence Act, 1872)",
    }


@app.get("/api/health", tags=["system"])
def health() -> dict:
    """Public health check endpoint for container orchestrators and status badges."""
    return {
        "status": "ok",
        "service": "aether-api",
        "version": "1.1.0",
        "intel_mode": resolve_intel_mode(),
    }


@app.get("/api/auth/whoami", tags=["system"])
def whoami(principal: InvestigatorPrincipal = Depends(verify_investigator_auth)) -> dict:
    """Report the authenticated principal's role and capabilities.

    The frontend reads this to decide which controls to render, and an auditor
    uses it to confirm which key is actually in play before doing anything.
    """
    return {
        "operator": principal.operator,
        "role": principal.role,
        "authenticated": principal.authenticated,
        "method": principal.method,
        "key_id": principal.key_id,
        "can_write": principal.can_write,
        "can_export": True,
        "can_confirm_export": principal.can_confirm_export,
    }


# ---------- Protected Custody & Audit Endpoints ---------- #

@app.get("/api/custody/verify", response_model=VerifyResult, tags=["custody"])
def custody_verify_alias(
    evidence_id: str = "AT-2026-0047",
    db: Session = Depends(get_db),
    principal: InvestigatorPrincipal = Depends(verify_investigator_auth),
) -> VerifyResult:
    """Cryptographically verify SHA-256 seal of the custody chain."""
    return verify_custody_chain(evidence_id, db=db, principal=principal)


@app.get("/api/audit-logs", response_model=list[AuditLogOut], tags=["audit"])
def get_audit_logs(
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db),
    principal: InvestigatorPrincipal = Depends(verify_investigator_auth),
) -> list[AuditLog]:
    """Retrieve immutable audit events for Section 63, Bharatiya Sakshya Adhiniyam, 2023 (formerly s.65B, Indian Evidence Act, 1872) judicial oversight."""
    logs = db.execute(
        select(AuditLog).order_by(AuditLog.id.desc()).offset(offset).limit(min(limit, 500))
    ).scalars().all()
    return logs
