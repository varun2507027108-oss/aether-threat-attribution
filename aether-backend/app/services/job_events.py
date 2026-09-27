"""Job Event Broadcaster & In-Memory Result Cache for Project AETHER.

Provides an asyncio-based pub-sub mechanism for streaming module-by-module
forensic progress over Server-Sent Events (SSE) without external message broker
dependencies (e.g. Redis).
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional


class JobEventBroadcaster:
    """Manages active SSE subscriber queues per investigation job ID."""

    def __init__(self) -> None:
        self._listeners: Dict[str, List[asyncio.Queue]] = {}
        self._lock = asyncio.Lock()
        self._results_cache: Dict[str, Dict[str, Any]] = {}

    async def subscribe(self, job_id: str) -> asyncio.Queue:
        """Register a new listener queue for the given job_id."""
        async with self._lock:
            q: asyncio.Queue = asyncio.Queue()
            if job_id not in self._listeners:
                self._listeners[job_id] = []
            self._listeners[job_id].append(q)
            return q

    async def unsubscribe(self, job_id: str, queue: asyncio.Queue) -> None:
        """Unregister a listener queue when the client disconnects or completes."""
        async with self._lock:
            if job_id in self._listeners:
                try:
                    self._listeners[job_id].remove(queue)
                except ValueError:
                    pass
                if not self._listeners[job_id]:
                    del self._listeners[job_id]

    async def publish(self, job_id: str, event: Dict[str, Any]) -> None:
        """Broadcast an event dictionary to all active listeners for job_id."""
        async with self._lock:
            queues = list(self._listeners.get(job_id, []))
        for q in queues:
            await q.put(event)

    def cache_result(self, job_id: str, result: Dict[str, Any]) -> None:
        """Cache the serialized forensic result for quick retrieval by snapshot endpoints."""
        self._results_cache[job_id] = result

    def get_cached_result(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve the cached forensic result if available."""
        return self._results_cache.get(job_id)


job_broadcaster = JobEventBroadcaster()
job_event_broadcaster = job_broadcaster
