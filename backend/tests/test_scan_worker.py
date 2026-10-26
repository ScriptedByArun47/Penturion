from app.core.database import get_db
from app.models.scan import Scan
from app.models.target import Target
from app.services.scan_service import process_next_scan
from unittest.mock import patch

from app.services.scan_service import ScanAuthorizationError

from datetime import datetime, timedelta, timezone
from app.services.scan_service import run_worker_cycle

from app.services.scan_service import recover_abandoned_scans

from tests.test_scan_lifecycle import (
    create_queued_scan,
    get_test_db,
)
from app.services.scan_service import (
    ScanLifecycleError,
    claim_next_scan,
    fail_running_scan,
    update_scan_heartbeat,
)


def test_worker_validates_authorized_scan_without_execution(
    auth_client, target_id
):
    scan_id = create_queued_scan(auth_client, target_id)

    db_generator, db = get_test_db(auth_client)

    try:
        processed = process_next_scan(db)

        assert processed is not None
        assert processed.id == scan_id
        assert processed.status == "running"
        assert processed.started_at is not None
        assert processed.completed_at is None
    finally:
        db_generator.close()


def test_worker_fails_scan_when_authorization_is_revoked(
    auth_client, target_id
):
    scan_id = create_queued_scan(auth_client, target_id)

    db_generator, db = get_test_db(auth_client)

    try:
        target = db.get(Target, target_id)
        assert target is not None

        target.authorization_status = "revoked"
        db.commit()

        processed = process_next_scan(db)

        assert processed is not None
        assert processed.id == scan_id
        assert processed.status == "failed"
        assert "no longer approved" in processed.error_message
        assert processed.completed_at is not None
    finally:
        db_generator.close()


def test_worker_returns_none_when_no_scans_are_queued(auth_client):
    db_generator, db = get_test_db(auth_client)

    try:
        processed = process_next_scan(db)
        assert processed is None
    finally:
        db_generator.close()


def test_worker_marks_scan_failed_on_unexpected_validation_error(
    auth_client, target_id
):
    scan_id = create_queued_scan(auth_client, target_id)

    db_generator, db = get_test_db(auth_client)

    try:
        with patch(
            "app.services.scan_service.validate_scan_for_execution",
            side_effect=RuntimeError("internal test exception"),
        ):
            processed = process_next_scan(db)

        assert processed is not None
        assert processed.id == scan_id
        assert processed.status == "failed"
        assert processed.error_message == (
            "Unexpected worker error during scan validation"
        )
        assert processed.completed_at is not None

    finally:
        db_generator.close()


def test_recovery_fails_abandoned_scan(auth_client, target_id):
    scan_id = create_queued_scan(auth_client, target_id)

    db_generator, db = get_test_db(auth_client)

    try:
        scan = process_next_scan(db)

        assert scan is not None
        assert scan.id == scan_id
        assert scan.status == "running"
        now = datetime.now(timezone.utc)
        scan.started_at = now - timedelta(minutes=45)
        scan.lease_expires_at = now - timedelta(minutes=15)
        db.commit()

        recovered = recover_abandoned_scans(db, timeout_minutes=30)

        assert recovered == 1

        db.refresh(scan)
        assert scan.status == "failed"
        assert scan.error_message == (
            "Scan timed out and was recovered as abandoned"
        )
        assert scan.completed_at is not None

    finally:
        db_generator.close()


def test_recovery_preserves_recent_running_scan(auth_client, target_id):
    create_queued_scan(auth_client, target_id)

    db_generator, db = get_test_db(auth_client)

    try:
        scan = process_next_scan(db)

        assert scan is not None
        assert scan.status == "running"

        recovered = recover_abandoned_scans(db, timeout_minutes=30)

        assert recovered == 0

        db.refresh(scan)
        assert scan.status == "running"
        assert scan.completed_at is None

    finally:
        db_generator.close()


def test_recovery_rejects_invalid_timeout(auth_client):
    db_generator, db = get_test_db(auth_client)

    try:
        try:
            recover_abandoned_scans(db, timeout_minutes=0)
            assert False, "Expected ValueError"
        except ValueError as exc:
            assert "greater than zero" in str(exc)

    finally:
        db_generator.close()


def test_worker_cycle_recovers_abandoned_scans_and_processes_queue(
    auth_client, target_id
):
    create_queued_scan(auth_client, target_id)

    db_generator, db = get_test_db(auth_client)

    try:
        first = process_next_scan(db)
        assert first is not None
        assert first.status == "running"

        now = datetime.now(timezone.utc)
        first.started_at = now - timedelta(minutes=45)
        first.lease_expires_at = now - timedelta(minutes=15)
        db.commit()

        second_id = create_queued_scan(auth_client, target_id)

        result = run_worker_cycle(db, timeout_minutes=30)

        assert result is not None
        assert result.id == second_id
        assert result.status == "running"

        db.refresh(first)
        assert first.status == "failed"

    finally:
        db_generator.close()


def test_worker_cycle_returns_none_when_queue_is_empty(auth_client):
    db_generator, db = get_test_db(auth_client)

    try:
        result = run_worker_cycle(db)

        assert result is None

    finally:
        db_generator.close()


def test_recovery_preserves_scan_with_recent_heartbeat(
    auth_client, target_id
):
    create_queued_scan(auth_client, target_id)

    db_generator, db = get_test_db(auth_client)

    try:
        scan = process_next_scan(db)
        assert scan is not None
        assert scan.status == "running"

        # Started 45 minutes ago, but heartbeat is recent.
        scan.started_at = datetime.now(timezone.utc) - timedelta(
            minutes=45
        )
        scan.last_heartbeat_at = datetime.now(timezone.utc)
        db.commit()

        recovered = recover_abandoned_scans(
            db, timeout_minutes=30
        )

        assert recovered == 0

        db.refresh(scan)
        assert scan.status == "running"

    finally:
        db_generator.close()


def test_recovery_fails_scan_with_stale_heartbeat(
    auth_client, target_id
):
    create_queued_scan(auth_client, target_id)

    db_generator, db = get_test_db(auth_client)

    try:
        scan = process_next_scan(db)
        assert scan is not None
        assert scan.status == "running"

        now = datetime.now(timezone.utc)
        scan.started_at = now - timedelta(minutes=60)
        scan.last_heartbeat_at = now - timedelta(minutes=45)
        scan.lease_expires_at = now - timedelta(minutes=15)
        db.commit()

        recovered = recover_abandoned_scans(
            db, timeout_minutes=30
        )

        assert recovered == 1

        db.refresh(scan)
        assert scan.status == "failed"

    finally:
        db_generator.close()
        

def test_worker_cannot_renew_another_workers_lease(
    auth_client, target_id
):
    create_queued_scan(auth_client, target_id)
    db_generator, db = get_test_db(auth_client)

    try:
        scan = claim_next_scan(db, worker_id="worker-A")
        assert scan is not None
        assert scan.status == "running"
        assert scan.worker_id == "worker-A"

        renewed = update_scan_heartbeat(
            db,
            scan_id=scan.id,
            worker_id="worker-B",
        )

        assert renewed is False

        db.refresh(scan)
        assert scan.worker_id == "worker-A"

    finally:
        db_generator.close()


def test_worker_can_renew_its_valid_lease(
    auth_client, target_id
):
    create_queued_scan(auth_client, target_id)
    db_generator, db = get_test_db(auth_client)

    try:
        scan = claim_next_scan(db, worker_id="worker-A")
        assert scan is not None

        previous_expiry = scan.lease_expires_at

        renewed = update_scan_heartbeat(
            db,
            scan_id=scan.id,
            worker_id="worker-A",
            lease_seconds=120,
        )

        assert renewed is True

        db.refresh(scan)
        assert scan.lease_expires_at > previous_expiry
        assert scan.last_heartbeat_at is not None

    finally:
        db_generator.close()


def test_worker_cannot_renew_expired_lease(
    auth_client, target_id
):
    create_queued_scan(auth_client, target_id)
    db_generator, db = get_test_db(auth_client)

    try:
        scan = claim_next_scan(db, worker_id="worker-A")
        assert scan is not None

        scan.lease_expires_at = (
            datetime.now(timezone.utc) - timedelta(seconds=10)
        )
        db.commit()

        renewed = update_scan_heartbeat(
            db,
            scan_id=scan.id,
            worker_id="worker-A",
        )

        assert renewed is False

        db.refresh(scan)
        assert scan.status == "running"

    finally:
        db_generator.close()


def test_worker_cannot_fail_scan_owned_by_another_worker(
    auth_client, target_id
):
    create_queued_scan(auth_client, target_id)
    db_generator, db = get_test_db(auth_client)

    try:
        scan = claim_next_scan(db, worker_id="worker-A")
        assert scan is not None

        try:
            fail_running_scan(
                db,
                scan_id=scan.id,
                error_message="Test failure",
                worker_id="worker-B",
            )
            assert False, "Expected ScanLifecycleError"
        except ScanLifecycleError:
            pass

        db.refresh(scan)
        assert scan.status == "running"
        assert scan.worker_id == "worker-A"

    finally:
        db_generator.close()


def test_worker_can_fail_scan_with_valid_lease(
    auth_client, target_id
):
    create_queued_scan(auth_client, target_id)
    db_generator, db = get_test_db(auth_client)

    try:
        scan = claim_next_scan(db, worker_id="worker-A")
        assert scan is not None
        assert scan.status == "running"

        failed_scan = fail_running_scan(
            db,
            scan_id=scan.id,
            error_message="Test failure",
            worker_id="worker-A",
        )

        assert failed_scan.status == "failed"
        assert failed_scan.error_message == "Test failure"
        assert failed_scan.completed_at is not None
        assert failed_scan.worker_id is None
        assert failed_scan.lease_expires_at is None

    finally:
        db_generator.close()

def test_expired_lease_is_recovered_even_with_recent_heartbeat(
    auth_client, target_id
):
    create_queued_scan(auth_client, target_id)
    db_generator, db = get_test_db(auth_client)

    try:
        scan = claim_next_scan(db, worker_id="worker-A")
        assert scan is not None

        now = datetime.now(timezone.utc)
        scan.last_heartbeat_at = now
        scan.lease_expires_at = now - timedelta(seconds=10)
        db.commit()

        recovered = recover_abandoned_scans(db)

        assert recovered == 1

        db.refresh(scan)
        assert scan.status == "failed"
        assert scan.worker_id is None
        assert scan.lease_expires_at is None

    finally:
        db_generator.close()