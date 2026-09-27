"""Investigation Jobs Router for Project AETHER.

Provides snapshot inspection and Server-Sent Events (SSE) streaming for
asynchronous forensic investigation jobs.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import logging
from typing import Any, AsyncGenerator, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Case, InvestigationJob
from app.schemas import InvestigationJobOut
from app.security import InvestigatorPrincipal, verify_investigator_auth
from app.services.job_events import job_broadcaster

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/jobs", tags=["jobs"])


def _get_job_or_404(db: Session, job_id: str) -> InvestigationJob:
    job = db.execute(select(InvestigationJob).where(InvestigationJob.id == job_id)).scalar_one_or_none()
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation job '{job_id}' not found.",
        )
    return job


@router.get("/{job_id}", response_model=InvestigationJobOut)
def get_job_snapshot(
    job_id: str,
    db: Session = Depends(get_db),
    principal: InvestigatorPrincipal = Depends(verify_investigator_auth),
) -> InvestigationJobOut:
    """Retrieve the current forensic execution snapshot of an investigation job."""
    job = _get_job_or_404(db, job_id)

    evidence_id = None
    if job.case_id:
        c = db.execute(select(Case).where(Case.id == job.case_id)).scalar_one_or_none()
        if c:
            evidence_id = c.evidence_id

    cached_result = job_broadcaster.get_cached_result(job_id)

    return InvestigationJobOut(
        id=job.id,
        case_id=job.case_id,
        evidence_id=evidence_id,
        status=job.status,
        error=job.error,
        modules=job.modules or [],
        created_at=job.created_at.isoformat() if job.created_at else None,
        updated_at=job.updated_at.isoformat() if job.updated_at else None,
        result=cached_result,
    )


@router.get("/{job_id}/events")
async def stream_job_events(
    job_id: str,
    request: Request,
    db: Session = Depends(get_db),
    principal: InvestigatorPrincipal = Depends(verify_investigator_auth),
) -> StreamingResponse:
    """Stream real-time forensic module execution updates via Server-Sent Events (SSE).
    
    Replays current module states on connect, streams live module updates,
    and cleanly terminates when the pipeline reaches a terminal status
    (complete, partial, or failed).
    """
    job = _get_job_or_404(db, job_id)

    evidence_id = None
    if job.case_id:
        c = db.execute(select(Case).where(Case.id == job.case_id)).scalar_one_or_none()
        if c:
            evidence_id = c.evidence_id

    cached_result = job_broadcaster.get_cached_result(job_id)

    initial_snapshot = {
        "type": "snapshot",
        "job_id": job.id,
        "evidence_id": evidence_id,
        "status": job.status,
        "modules": job.modules or [],
        "created_at": job.created_at.isoformat() if job.created_at else None,
        "updated_at": job.updated_at.isoformat() if job.updated_at else None,
        "result": cached_result,
    }

    async def sse_generator() -> AsyncGenerator[str, None]:
        # 1. Replay current snapshot state immediately
        yield f"event: snapshot\ndata: {json.dumps(initial_snapshot, default=str)}\n\n"

        # If job has already completed prior to this SSE connection
        if job.status in ("complete", "partial", "failed"):
            terminal_event = {
                "type": "terminal",
                "job_id": job.id,
                "status": job.status,
                "evidence_id": evidence_id,
                "error": job.error,
                "result": cached_result,
            }
            yield f"event: terminal\ndata: {json.dumps(terminal_event, default=str)}\n\n"
            return

        # 2. Subscribe to live broadcaster queue
        queue = await job_broadcaster.subscribe(job_id)
        try:
            while True:
                # Disconnect check
                if await request.is_disconnected():
                    logger.debug("SSE client disconnected for job %s", job_id)
                    break

                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15.0)
                    event_type = event.get("type", "module_update")
                    yield f"event: {event_type}\ndata: {json.dumps(event, default=str)}\n\n"

                    if event_type == "terminal" or event.get("status") in ("complete", "partial", "failed"):
                        break
                except asyncio.TimeoutError:
                    # Keep-alive comment to prevent proxy/browser timeout
                    yield ": keep-alive\n\n"
        finally:
            await job_broadcaster.unsubscribe(job_id, queue)

    return StreamingResponse(
        sse_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
