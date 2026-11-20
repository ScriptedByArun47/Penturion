"""Background scan lease heartbeat management."""

import logging
import threading
from collections.abc import Callable
from typing import Any

from sqlalchemy.orm import Session

logger = logging.getLogger("penturion.heartbeat")


HeartbeatCallback = Callable[
    [Session, str, str, int],
    bool,
]


class ScanHeartbeatKeeper:
    """Renew a scan lease using independent database sessions."""

    def __init__(
        self,
        session_factory: Callable[[], Session],
        heartbeat_callback: HeartbeatCallback,
        scan_id: str,
        worker_id: str,
        lease_seconds: int = 60,
        heartbeat_interval: int = 20,
        cancel_event: threading.Event | None = None,
    ) -> None:
        if not callable(session_factory):
            raise TypeError("session_factory must be callable")

        if not callable(heartbeat_callback):
            raise TypeError("heartbeat_callback must be callable")

        if not scan_id or not scan_id.strip():
            raise ValueError("scan_id cannot be empty")

        if not worker_id or not worker_id.strip():
            raise ValueError("worker_id cannot be empty")

        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")

        if heartbeat_interval <= 0:
            raise ValueError("heartbeat_interval must be positive")

        if heartbeat_interval >= lease_seconds:
            raise ValueError(
                "heartbeat_interval must be shorter than lease_seconds"
            )

        self._session_factory = session_factory
        self._heartbeat_callback = heartbeat_callback
        self._scan_id = scan_id
        self._worker_id = worker_id
        self._lease_seconds = lease_seconds
        self._heartbeat_interval = heartbeat_interval

        self.cancel_event = cancel_event or threading.Event()

        self._stop_event = threading.Event()
        self._state_lock = threading.Lock()

        self._lease_lost = False
        self._failure_reason: str | None = None

        self._thread: threading.Thread | None = None

    @property
    def lease_lost(self) -> bool:
        with self._state_lock:
            return self._lease_lost

    @property
    def failure_reason(self) -> str | None:
        with self._state_lock:
            return self._failure_reason

    def start(self) -> None:
        """Start the background heartbeat thread."""

        if self._thread is not None:
            raise RuntimeError("Heartbeat keeper has already been started")

        if self.cancel_event.is_set():
            raise RuntimeError("Cannot start with cancellation already requested")

        self._thread = threading.Thread(
            target=self._run,
            name=f"heartbeat-{self._scan_id}",
            daemon=True,
        )

        self._thread.start()

    def stop(self, timeout: float = 5.0) -> bool:
        """Request shutdown and wait for the heartbeat thread."""

        if timeout < 0:
            raise ValueError("timeout cannot be negative")

        self._stop_event.set()

        if self._thread is None:
            return True

        self._thread.join(timeout=timeout)

        return not self._thread.is_alive()

    def _mark_lease_lost(self, reason: str) -> None:
        """Record lease loss and notify the running scan."""

        with self._state_lock:
            self._lease_lost = True
            self._failure_reason = reason[:2000]

        self.cancel_event.set()

        logger.error(
            "Scan lease lost: scan_id=%s worker_id=%s reason=%s",
            self._scan_id,
            self._worker_id,
            reason,
        )

    def _renew_lease(self) -> bool:
        """Renew the lease using a separate database session."""

        db: Session | None = None
        renewed = False
        failure_reason: str | None = None

        try:
            db = self._session_factory()

            renewed = self._heartbeat_callback(
                db,
                self._scan_id,
                self._worker_id,
                self._lease_seconds,
            )

            if not renewed:
                failure_reason = (
                    "Heartbeat rejected: worker no longer owns a valid lease"
                )

        except Exception as exc:
            failure_reason = (
                f"Heartbeat database error: {type(exc).__name__}: {exc}"
            )

        finally:
            if db is not None:
                try:
                    db.close()
                except Exception as exc:
                    failure_reason = (
                        f"Database session close failed: "
                        f"{type(exc).__name__}: {exc}"
                    )

        if failure_reason is not None:
            self._mark_lease_lost(failure_reason)
            return False

        return renewed

    def _run(self) -> None:
        """Run periodic lease renewal until stopped or lease loss."""

        while not self._stop_event.wait(self._heartbeat_interval):
            if self.cancel_event.is_set():
                return

            if not self._renew_lease():
                return