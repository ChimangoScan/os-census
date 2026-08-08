"""The job-queue abstract interface both backends (``SqliteQueue``, ``HttpQueue``) implement.

Defines the job lifecycle (``pending -> running -> {done | failed | skipped}``)
and the claim/heartbeat/complete-or-fail-or-skip contract every worker drives
a job through. See ``STATUSES`` for what each terminal state means."""
from __future__ import annotations
from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass

from ..models import Target

# Job lifecycle: pending -> running -> {done | failed | skipped}.
#   failed  = transient error, attempts exhausted
#   skipped = permanent, won't be retried (e.g. image too large, manifest gone)
STATUSES = ("pending", "running", "done", "failed", "skipped")


@dataclass
class Job:
    """One target's slot in the queue: its id, the target to scan, and attempts made so far."""

    id: int
    target: Target
    attempts: int


class Queue(ABC):
    """A work queue plus a results sink. Safe for concurrent claimers; in the
    distributed setup every worker talks to the same instance over HTTP."""

    # ── producing work ──────────────────────────────────────────────────────
    @abstractmethod
    def seed(self, targets: list[Target]) -> int:
        """Insert targets that aren't already queued. Returns how many were new."""

    # ── consuming work ──────────────────────────────────────────────────────
    @abstractmethod
    def claim(self, worker_id: str) -> Job | None:
        """Atomically take the next pending job (highest weight first)."""

    @abstractmethod
    def heartbeat(self, job_id: int, worker_id: str) -> None:
        """Refresh the liveness timestamp for a running job so ``reset_stale`` won't reclaim it."""

    @abstractmethod
    def complete(self, job_id: int, worker_id: str, report: dict) -> None:
        """Mark the job ``done`` and store ``report`` as its result, retrievable via ``iter_reports``."""

    @abstractmethod
    def fail(self, job_id: int, worker_id: str, error: str, max_attempts: int) -> None:
        """Record a transient failure. Requeues to ``pending`` unless ``attempts`` has reached ``max_attempts``, in which case the job becomes ``failed``."""

    @abstractmethod
    def skip(self, job_id: int, worker_id: str, reason: str) -> None:
        """Mark the job ``skipped``: a permanent condition (not a transient error), never retried by ``reset_stale`` or normal claiming."""

    # ── housekeeping / introspection ────────────────────────────────────────
    @abstractmethod
    def reset_stale(self, stale_minutes: int) -> int:
        """Requeue running jobs whose heartbeat is older than `stale_minutes`."""

    @abstractmethod
    def reset(self, *, failed: bool = False, skipped: bool = False, done: bool = False) -> int:
        """Requeue failed and/or skipped jobs."""

    @abstractmethod
    def stats(self) -> dict:
        """Return a count of jobs per status in ``STATUSES``."""

    @abstractmethod
    def iter_reports(self) -> Iterator[dict]:
        """Yield every stored per-target report (for building the corpus view)."""

    def close(self) -> None:
        """Release any held resources (connections, sockets). No-op by default."""
