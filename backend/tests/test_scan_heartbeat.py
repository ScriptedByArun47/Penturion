import threading

import pytest

from app.scanners.heartbeat import ScanHeartbeatKeeper


class FakeSession:
    def __init__(self, close_error=None):
        self.closed = False
        self.close_error = close_error

    def close(self):
        self.closed = True

        if self.close_error:
            raise self.close_error


def make_keeper(
    callback,
    session=None,
    cancel_event=None,
    heartbeat_interval=0.01,
):
    fake_session = session or FakeSession()

    keeper = ScanHeartbeatKeeper(
        session_factory=lambda: fake_session,
        heartbeat_callback=callback,
        scan_id="test-scan",
        worker_id="test-worker",
        lease_seconds=10,
        heartbeat_interval=heartbeat_interval,
        cancel_event=cancel_event,
    )

    return keeper, fake_session


def test_successful_heartbeat():
    called = threading.Event()

    def callback(db, scan_id, worker_id, lease_seconds):
        called.set()
        return True

    keeper, session = make_keeper(callback)

    keeper.start()

    assert called.wait(timeout=2)
    assert keeper.stop(timeout=2) is True

    assert keeper.lease_lost is False
    assert keeper.failure_reason is None
    assert session.closed is True


def test_rejected_heartbeat_signals_cancellation():
    cancel_event = threading.Event()

    def callback(db, scan_id, worker_id, lease_seconds):
        return False

    keeper, _ = make_keeper(
        callback,
        cancel_event=cancel_event,
    )

    keeper.start()

    assert cancel_event.wait(timeout=2)
    assert keeper.stop(timeout=2) is True

    assert keeper.lease_lost is True
    assert keeper.failure_reason is not None


def test_heartbeat_exception_signals_cancellation():
    cancel_event = threading.Event()

    def callback(db, scan_id, worker_id, lease_seconds):
        raise RuntimeError("Database unavailable")

    keeper, session = make_keeper(
        callback,
        cancel_event=cancel_event,
    )

    keeper.start()

    assert cancel_event.wait(timeout=2)
    assert keeper.stop(timeout=2) is True

    assert keeper.lease_lost is True
    assert "Database unavailable" in keeper.failure_reason
    assert session.closed is True


def test_session_close_exception_signals_cancellation():
    cancel_event = threading.Event()

    session = FakeSession(
        close_error=RuntimeError("Session close failed")
    )

    def callback(db, scan_id, worker_id, lease_seconds):
        return True

    keeper, _ = make_keeper(
        callback,
        session=session,
        cancel_event=cancel_event,
    )

    keeper.start()

    assert cancel_event.wait(timeout=2)
    assert keeper.stop(timeout=2) is True

    assert keeper.lease_lost is True
    assert "Session close failed" in keeper.failure_reason


def test_stop_before_next_heartbeat():
    called = threading.Event()

    def callback(db, scan_id, worker_id, lease_seconds):
        called.set()
        return True

    keeper, _ = make_keeper(
        callback,
        heartbeat_interval=5,
    )

    keeper.start()

    assert keeper.stop(timeout=2) is True
    assert called.is_set() is False
    assert keeper.lease_lost is False


def test_invalid_heartbeat_interval():
    with pytest.raises(ValueError):
        ScanHeartbeatKeeper(
            session_factory=FakeSession,
            heartbeat_callback=lambda *args: True,
            scan_id="test-scan",
            worker_id="test-worker",
            lease_seconds=10,
            heartbeat_interval=10,
        )


def test_cannot_start_twice():
    keeper, _ = make_keeper(
        lambda *args: True,
        heartbeat_interval=5,
    )

    keeper.start()

    with pytest.raises(RuntimeError):
        keeper.start()

    assert keeper.stop(timeout=2) is True

def test_cancellation_request_signals_scanner_without_losing_lease():
    cancel_event = threading.Event()

    def heartbeat_callback(db, scan_id, worker_id, lease_seconds):
        return True

    def cancellation_callback(db, scan_id, worker_id):
        return True

    keeper, session = make_keeper(
        heartbeat_callback,
        cancel_event=cancel_event,
        heartbeat_interval=0.01,
    )

    keeper._cancellation_callback = cancellation_callback

    keeper.start()

    assert cancel_event.wait(timeout=2)
    assert keeper.stop(timeout=2) is True

    assert keeper.cancellation_requested is True
    assert keeper.lease_lost is False
    assert session.closed is True
