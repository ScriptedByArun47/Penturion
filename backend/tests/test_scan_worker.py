from app.core.database import get_db
from app.models.scan import Scan
from app.models.target import Target
from app.services.scan_service import process_next_scan
from unittest.mock import patch
import pytest
from app.services.scan_service import ScanAuthorizationError

from app.models.finding import Finding
from app.scanners.base import ScanFinding, ScannerResult

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
    complete_running_scan,
    fail_running_scan,
    update_scan_heartbeat,
)

def test_worker_executes_scanner_and_completes_scan(
    auth_client, target_id
):
    scan_id = create_queued_scan(auth_client, target_id)

    db_generator, db = get_test_db(auth_client)

    mock_result = ScannerResult(
        scanner_name="http",
        target="https://scan-test.example.com/",
        success=True,
        findings=(),
    )

    try:
        with patch(
            "app.services.scan_service.HTTPScanner.execute",
            return_value=mock_result,
        ) as mock_execute:
            processed = process_next_scan(db)

        assert processed is not None
        assert processed.id == scan_id
        assert processed.status == "completed"
        assert processed.started_at is not None
        assert processed.completed_at is not None

        mock_execute.assert_called_once_with(
            "https://scan-test.example.com/"
        )

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
          "Unexpected worker error during HTTP scanning"
        )
        assert processed.completed_at is not None

    finally:
        db_generator.close()


def test_recovery_fails_abandoned_scan(auth_client, target_id):
    scan_id = create_queued_scan(auth_client, target_id)

    db_generator, db = get_test_db(auth_client)

    try:
        scan = claim_next_scan(db)

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
        scan = claim_next_scan(db)

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
        first = claim_next_scan(db)
        assert first is not None
        assert first.status == "running"

        now = datetime.now(timezone.utc)
        first.started_at = now - timedelta(minutes=45)
        first.lease_expires_at = now - timedelta(minutes=15)
        db.commit()

        second_id = create_queued_scan(auth_client, target_id)

        mock_result = ScannerResult(
            scanner_name="http",
            target="https://scan-test.example.com/",
            success=True,
            findings=(),
        )

        with patch(
            "app.services.scan_service.HTTPScanner.execute",
            return_value=mock_result,
        ):
            result = run_worker_cycle(db, timeout_minutes=30)

        assert result is not None
        assert result.id == second_id
        assert result.status == "completed"

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
        scan = claim_next_scan(db)
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
        scan = claim_next_scan(db)
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
        
def test_worker_cannot_fail_scan_after_lease_expires(
    auth_client, target_id
):
    create_queued_scan(auth_client, target_id)
    db_generator, db = get_test_db(auth_client)

    try:
        scan = claim_next_scan(db, worker_id="worker-A")
        assert scan is not None
        assert scan.status == "running"

        # Simulate an expired lease.
        scan.lease_expires_at = (
            datetime.now(timezone.utc) - timedelta(seconds=10)
        )
        db.commit()

        with pytest.raises(ScanLifecycleError):
            fail_running_scan(
                db=db,
                scan_id=scan.id,
                error_message="Test failure",
                worker_id="worker-A",
            )

        db.refresh(scan)
        assert scan.status == "running"
        assert scan.worker_id == "worker-A"

    finally:
        db_generator.close()
def test_only_one_worker_can_claim_a_queued_scan(
    auth_client, target_id
):
    scan_id = create_queued_scan(auth_client, target_id)

    db_generator, db = get_test_db(auth_client)

    try:
        first_claim = claim_next_scan(
            db,
            worker_id="worker-A",
        )

        assert first_claim is not None
        assert first_claim.id == scan_id
        assert first_claim.status == "running"
        assert first_claim.worker_id == "worker-A"

        second_claim = claim_next_scan(
            db,
            worker_id="worker-B",
        )

        assert second_claim is None

        db.expire_all()
        stored_scan = db.get(Scan, scan_id)

        assert stored_scan is not None
        assert stored_scan.status == "running"
        assert stored_scan.worker_id == "worker-A"

    finally:
        db_generator.close()
def test_worker_can_complete_scan_with_valid_lease(
    auth_client, target_id
):
    create_queued_scan(auth_client, target_id)
    db_generator, db = get_test_db(auth_client)

    try:
        scan = claim_next_scan(db, worker_id="worker-A")
        assert scan is not None

        completed = complete_running_scan(
            db,
            scan.id,
            worker_id="worker-A",
        )

        assert completed.status == "completed"
        assert completed.completed_at is not None
        assert completed.worker_id is None
        assert completed.lease_expires_at is None

    finally:
        db_generator.close()
        
def test_worker_cannot_complete_another_workers_scan(
    auth_client, target_id
):
    create_queued_scan(auth_client, target_id)
    db_generator, db = get_test_db(auth_client)

    try:
        scan = claim_next_scan(db, worker_id="worker-A")
        assert scan is not None

        with pytest.raises(ScanLifecycleError):
            complete_running_scan(
                db,
                scan.id,
                worker_id="worker-B",
            )

        db.refresh(scan)
        assert scan.status == "running"
        assert scan.worker_id == "worker-A"

    finally:
        db_generator.close()
    
def test_worker_cannot_complete_scan_after_lease_expires(
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

        with pytest.raises(ScanLifecycleError):
            complete_running_scan(
                db,
                scan.id,
                worker_id="worker-A",
            )

        db.refresh(scan)
        assert scan.status == "running"
        assert scan.worker_id == "worker-A"

    finally:
        db_generator.close()
        
def test_worker_fails_queued_scan_after_authorization_api_revocation(
    auth_client, target_id
):
    # 1. Create a scan with approved authorization.
    scan_id = create_queued_scan(auth_client, target_id)

    # 2. Retrieve the authorization request ID linked to the scan.
    db_generator, db = get_test_db(auth_client)

    try:
        scan = db.get(Scan, scan_id)
        assert scan is not None

        authorization_request_id = scan.authorization_request_id
        assert authorization_request_id is not None
    finally:
        db_generator.close()

    # 3. Revoke authorization through the actual API.
    revoke_response = auth_client.patch(
        f"/api/v1/authorization-requests/"
        f"{authorization_request_id}/revoke"
    )

    assert revoke_response.status_code == 200
    assert revoke_response.json()["status"] == "revoked"

    # 4. Let the worker process the queued scan.
    db_generator, db = get_test_db(auth_client)

    try:
        processed = process_next_scan(db)

        # 5. Verify that execution was denied.
        assert processed is not None
        assert processed.id == scan_id
        assert processed.status == "failed"
        assert "no longer approved" in processed.error_message
        assert processed.completed_at is not None

    finally:
        db_generator.close()

def test_worker_persists_scanner_findings(
    auth_client, target_id
):
    scan_id = create_queued_scan(auth_client, target_id)

    db_generator, db = get_test_db(auth_client)

    mock_finding = ScanFinding(
        title="Missing Content-Security-Policy header",
        severity="low",
        description="The application does not return a CSP header.",
        evidence={
            "missing_header": "content-security-policy",
            "http_status": 200,
        },
        remediation="Configure an appropriate Content-Security-Policy.",
    )

    mock_result = ScannerResult(
        scanner_name="http",
        target="https://scan-test.example.com/",
        success=True,
        findings=(mock_finding,),
    )

    try:
        with patch(
            "app.services.scan_service.HTTPScanner.execute",
            return_value=mock_result,
        ):
            processed = process_next_scan(db)

        assert processed is not None
        assert processed.status == "completed"

        findings = (
            db.query(Finding)
            .filter(Finding.scan_id == scan_id)
            .all()
        )

        assert len(findings) == 1
        assert findings[0].scanner_name == "http"
        assert findings[0].severity == "low"
        assert findings[0].evidence["http_status"] == 200

    finally:
        db_generator.close()
        
def test_worker_fails_when_http_scanner_fails(
    auth_client, target_id
):
    scan_id = create_queued_scan(auth_client, target_id)

    db_generator, db = get_test_db(auth_client)

    mock_result = ScannerResult(
        scanner_name="http",
        target="https://scan-test.example.com/",
        success=False,
        error="HTTP request timed out",
    )

    try:
        with patch(
            "app.services.scan_service.HTTPScanner.execute",
            return_value=mock_result,
        ):
            processed = process_next_scan(db)

        assert processed is not None
        assert processed.id == scan_id
        assert processed.status == "failed"
        assert processed.error_message == "HTTP request timed out"

    finally:
        db_generator.close()
        
def test_worker_renews_lease_during_long_running_scan(
    tmp_path,
    monkeypatch,
):
    import json
    import threading

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import app.services.scan_service as scan_service

    from app.core.database import Base
    from app.models.user import User
    from app.models.project import Project
    from app.models.target import Target
    from app.models.authorization import AuthorizationRequest
    from app.models.scan import Scan
    from app.scanners.heartbeat import ScanHeartbeatKeeper
    from app.scanners.base import ScannerResult

    # Create a file-backed SQLite database.
    database_path = tmp_path / "heartbeat_test.db"

    engine = create_engine(
        f"sqlite:///{database_path}",
        connect_args={"check_same_thread": False},
    )

    TestSessionLocal = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=engine,
    )

    Base.metadata.create_all(bind=engine)

    heartbeat_observed = threading.Event()

    try:
        # Seed a valid user, project, target, authorization and scan.
        with TestSessionLocal() as db:
            user = User(
                email="heartbeat-test@example.com",
                password_hash="test-hash",
                role="user",
                is_active=True,
            )
            db.add(user)
            db.flush()

            project = Project(
                owner_id=user.id,
                name="Heartbeat Integration Test",
            )
            db.add(project)
            db.flush()

            target = Target(
                project_id=project.id,
                value="heartbeat-test.example.com",
                target_type="domain",
                authorization_status="approved",
            )
            db.add(target)
            db.flush()

            authorization = AuthorizationRequest(
                target_id=target.id,
                status="approved",
                evidence_reference="heartbeat-test-authorization",
                requested_scope=json.dumps([target.value]),
                requested_by="test-requester",
            )
            db.add(authorization)
            db.flush()

            scan = Scan(
                target_id=target.id,
                authorization_request_id=authorization.id,
                requested_by=user.id,
                scan_type="web",
                status="queued",
            )
            db.add(scan)
            db.commit()

            scan_id = scan.id

        # Use the real keeper with a shorter interval for this test.
        def fast_keeper(**kwargs):
            kwargs["heartbeat_interval"] = 0.05
            return ScanHeartbeatKeeper(**kwargs)

        monkeypatch.setattr(
            scan_service,
            "ScanHeartbeatKeeper",
            fast_keeper,
        )

        # Observe successful real heartbeat renewals.
        original_update = scan_service.update_scan_heartbeat

        def observed_heartbeat(*args, **kwargs):
            renewed = original_update(*args, **kwargs)

            if renewed:
                heartbeat_observed.set()

            return renewed

        monkeypatch.setattr(
            scan_service,
            "update_scan_heartbeat",
            observed_heartbeat,
        )

        # Keep the scanner running until a heartbeat is received.
        def slow_scanner(self, target_url):
            assert heartbeat_observed.wait(timeout=3), (
                "Heartbeat was not received while scanner was running"
            )

            return ScannerResult(
                scanner_name="HTTPScanner",
                target=target_url,
                success=True,
            )

        monkeypatch.setattr(
            scan_service.HTTPScanner,
            "execute",
            slow_scanner,
        )

        # Execute using independent database sessions.
        with TestSessionLocal() as db:
            result = scan_service.process_next_scan(
                db,
                heartbeat_session_factory=TestSessionLocal,
            )

            assert result is not None
            assert result.id == scan_id
            assert result.status == "completed"

        # Confirm the heartbeat was actually recorded in the database.
        with TestSessionLocal() as db:
            completed_scan = db.get(Scan, scan_id)

            assert completed_scan is not None
            assert completed_scan.last_heartbeat_at is not None
            assert completed_scan.lease_expires_at is None
            assert completed_scan.status == "completed"

    finally:
        Base.metadata.drop_all(bind=engine)
        engine.dispose()

def test_worker_does_not_complete_scan_after_heartbeat_failure(
    tmp_path,
    monkeypatch,
):
    import json
    import threading

    from sqlalchemy import create_engine, select, func
    from sqlalchemy.orm import sessionmaker

    import app.services.scan_service as scan_service

    from app.core.database import Base
    from app.models.user import User
    from app.models.project import Project
    from app.models.target import Target
    from app.models.authorization import AuthorizationRequest
    from app.models.scan import Scan
    from app.models.finding import Finding
    from app.scanners.heartbeat import ScanHeartbeatKeeper
    from app.scanners.base import ScannerResult, ScanFinding

    database_path = tmp_path / "heartbeat_failure_test.db"

    engine = create_engine(
        f"sqlite:///{database_path}",
        connect_args={"check_same_thread": False},
    )

    TestSessionLocal = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=engine,
    )

    Base.metadata.create_all(bind=engine)

    heartbeat_attempted = threading.Event()

    try:
        # Create valid scan records.
        with TestSessionLocal() as db:
            user = User(
                email="heartbeat-failure@example.com",
                password_hash="test-hash",
                role="user",
                is_active=True,
            )
            db.add(user)
            db.flush()

            project = Project(
                owner_id=user.id,
                name="Heartbeat Failure Test",
            )
            db.add(project)
            db.flush()

            target = Target(
                project_id=project.id,
                value="heartbeat-failure.example.com",
                target_type="domain",
                authorization_status="approved",
            )
            db.add(target)
            db.flush()

            authorization = AuthorizationRequest(
                target_id=target.id,
                status="approved",
                evidence_reference="heartbeat-failure-authorization",
                requested_scope=json.dumps([target.value]),
                requested_by="test-requester",
            )
            db.add(authorization)
            db.flush()

            scan = Scan(
                target_id=target.id,
                authorization_request_id=authorization.id,
                requested_by=user.id,
                scan_type="web",
                status="queued",
            )
            db.add(scan)
            db.commit()

            scan_id = scan.id

        # Use the real heartbeat keeper with a short interval.
        def fast_keeper(**kwargs):
            kwargs["heartbeat_interval"] = 0.05
            return ScanHeartbeatKeeper(**kwargs)

        monkeypatch.setattr(
            scan_service,
            "ScanHeartbeatKeeper",
            fast_keeper,
        )

        # Simulate rejection of heartbeat renewal.
        def rejected_heartbeat(
            db,
            scan_id,
            worker_id,
            lease_seconds,
        ):
            heartbeat_attempted.set()
            return False

        monkeypatch.setattr(
            scan_service,
            "update_scan_heartbeat",
            rejected_heartbeat,
        )

        # Return a finding after the heartbeat attempt.
        def slow_scanner(self, target_url):
            assert heartbeat_attempted.wait(timeout=3), (
                "Heartbeat was not attempted during scanner execution"
            )

            return ScannerResult(
                scanner_name="HTTPScanner",
                target=target_url,
                success=True,
                findings=(
                    ScanFinding(
                        title="Test finding",
                        severity="high",
                        description="Integration test finding",
                    ),
                ),
            )

        monkeypatch.setattr(
            scan_service.HTTPScanner,
            "execute",
            slow_scanner,
        )

        # A lost lease must prevent scan completion.
        from app.services.scan_service import ScanLifecycleError

        with TestSessionLocal() as db:
            with pytest.raises(ScanLifecycleError):
                scan_service.process_next_scan(
                    db,
                    heartbeat_session_factory=TestSessionLocal,
                )

        # Verify that no findings were committed.
        with TestSessionLocal() as db:
            completed_scan = db.get(Scan, scan_id)

            assert completed_scan is not None
            assert completed_scan.status == "running"
            assert completed_scan.worker_id is not None

            finding_count = db.scalar(
                select(func.count())
                .select_from(Finding)
                .where(Finding.scan_id == scan_id)
            )

            assert finding_count == 0

    finally:
        Base.metadata.drop_all(bind=engine)
        engine.dispose()
        
def test_worker_cannot_complete_scan_after_ownership_takeover(
    tmp_path,
    monkeypatch,
):
    import json
    import threading
    import time

    from sqlalchemy import create_engine, select, func, update
    from sqlalchemy.orm import sessionmaker

    import app.services.scan_service as scan_service

    from app.core.database import Base
    from app.models.user import User
    from app.models.project import Project
    from app.models.target import Target
    from app.models.authorization import AuthorizationRequest
    from app.models.scan import Scan
    from app.models.finding import Finding
    from app.scanners.heartbeat import ScanHeartbeatKeeper
    from app.scanners.base import ScannerResult, ScanFinding
    from app.services.scan_service import ScanLifecycleError

    engine = create_engine(
        f"sqlite:///{tmp_path / 'ownership_test.db'}",
        connect_args={"check_same_thread": False},
    )

    TestSessionLocal = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=engine,
    )

    Base.metadata.create_all(bind=engine)

    heartbeat_attempted = threading.Event()
    keepers = []

    try:
        with TestSessionLocal() as db:
            user = User(
                email="ownership-test@example.com",
                password_hash="test-hash",
                role="user",
                is_active=True,
            )
            db.add(user)
            db.flush()

            project = Project(
                owner_id=user.id,
                name="Ownership Takeover Test",
            )
            db.add(project)
            db.flush()

            target = Target(
                project_id=project.id,
                value="ownership-test.example.com",
                target_type="domain",
                authorization_status="approved",
            )
            db.add(target)
            db.flush()

            authorization = AuthorizationRequest(
                target_id=target.id,
                status="approved",
                evidence_reference="ownership-test-authorization",
                requested_scope=json.dumps([target.value]),
                requested_by="test-requester",
            )
            db.add(authorization)
            db.flush()

            scan = Scan(
                target_id=target.id,
                authorization_request_id=authorization.id,
                requested_by=user.id,
                scan_type="web",
                status="queued",
            )
            db.add(scan)
            db.commit()

            scan_id = scan.id

        # Use the real keeper with a short heartbeat interval.
        def fast_keeper(**kwargs):
            kwargs["heartbeat_interval"] = 0.05

            keeper = ScanHeartbeatKeeper(**kwargs)
            keepers.append(keeper)

            return keeper

        monkeypatch.setattr(
            scan_service,
            "ScanHeartbeatKeeper",
            fast_keeper,
        )

        original_update = scan_service.update_scan_heartbeat

        # Simulate another worker taking ownership before renewal.
        def takeover_then_heartbeat(
            db,
            scan_id,
            worker_id,
            lease_seconds,
        ):
            db.execute(
                update(Scan)
                .where(Scan.id == scan_id)
                .values(worker_id="replacement-worker")
            )
            db.commit()

            renewed = original_update(
                db,
                scan_id,
                worker_id,
                lease_seconds,
            )

            heartbeat_attempted.set()

            return renewed

        monkeypatch.setattr(
            scan_service,
            "update_scan_heartbeat",
            takeover_then_heartbeat,
        )

        def slow_scanner(self, target_url):
            assert heartbeat_attempted.wait(timeout=3)

            # Wait until the keeper has recorded lease loss.
            deadline = time.monotonic() + 2

            while time.monotonic() < deadline:
                if keepers and keepers[0].lease_lost:
                    break
                time.sleep(0.01)

            assert keepers[0].lease_lost

            return ScannerResult(
                scanner_name="HTTPScanner",
                target=target_url,
                success=True,
                findings=(
                    ScanFinding(
                        title="Ownership test finding",
                        severity="high",
                        description="Must not be persisted.",
                    ),
                ),
            )

        monkeypatch.setattr(
            scan_service.HTTPScanner,
            "execute",
            slow_scanner,
        )

        with TestSessionLocal() as db:
            with pytest.raises(ScanLifecycleError):
                scan_service.process_next_scan(
                    db,
                    heartbeat_session_factory=TestSessionLocal,
                )

        # Verify that the original worker did not complete the scan.
        with TestSessionLocal() as db:
            stored_scan = db.get(Scan, scan_id)

            assert stored_scan is not None
            assert stored_scan.status == "running"
            assert stored_scan.worker_id == "replacement-worker"

            finding_count = db.scalar(
                select(func.count())
                .select_from(Finding)
                .where(Finding.scan_id == scan_id)
            )

            assert finding_count == 0

    finally:
        Base.metadata.drop_all(bind=engine)
        engine.dispose()

def test_worker_cancels_running_scan_without_persisting_findings(
    tmp_path,
    monkeypatch,
):
    import json
    import threading

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import app.services.scan_service as scan_service

    from app.core.database import Base
    from app.models.user import User
    from app.models.project import Project
    from app.models.target import Target
    from app.models.authorization import AuthorizationRequest
    from app.models.scan import Scan
    from app.models.finding import Finding
    from app.scanners.heartbeat import ScanHeartbeatKeeper
    from app.scanners.base import ScanFinding, ScannerResult

    engine = create_engine(
        f"sqlite:///{tmp_path / 'cancellation_test.db'}",
        connect_args={"check_same_thread": False},
    )

    TestSessionLocal = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=engine,
    )

    Base.metadata.create_all(bind=engine)

    cancellation_observed = threading.Event()

    try:
        with TestSessionLocal() as db:
            user = User(
                email="cancellation-test@example.com",
                password_hash="test-hash",
                role="user",
                is_active=True,
            )
            db.add(user)
            db.flush()

            user_id = user.id

            project = Project(
                owner_id=user.id,
                name="Cancellation Integration Test",
            )
            db.add(project)
            db.flush()

            target = Target(
                project_id=project.id,
                value="cancellation-test.example.com",
                target_type="domain",
                authorization_status="approved",
            )
            db.add(target)
            db.flush()

            authorization = AuthorizationRequest(
                target_id=target.id,
                status="approved",
                evidence_reference="cancellation-test-authorization",
                requested_scope=json.dumps([target.value]),
                requested_by="test-requester",
            )
            db.add(authorization)
            db.flush()

            scan = Scan(
                target_id=target.id,
                authorization_request_id=authorization.id,
                requested_by=user.id,
                scan_type="web",
                status="queued",
            )
            db.add(scan)
            db.commit()

            scan_id = scan.id

        def fast_keeper(**kwargs):
            kwargs["heartbeat_interval"] = 0.05
            return ScanHeartbeatKeeper(**kwargs)

        monkeypatch.setattr(
            scan_service,
            "ScanHeartbeatKeeper",
            fast_keeper,
        )

        def scanner_with_cancellation(self, target_url):
            # Simulate cancellation from another API request.
            with TestSessionLocal() as cancel_db:
                requested = scan_service.request_scan_cancellation(
                    db=cancel_db,
                    scan_id=scan_id,
                    owner_id=user_id,
                )

                assert requested.status == "running"
                assert requested.cancel_requested_at is not None

            # Wait until the heartbeat keeper detects cancellation.
            assert self.cancel_event.wait(timeout=3), (
                "Worker did not detect the cancellation request"
            )

            cancellation_observed.set()

            # Return a finding deliberately. It must not be persisted.
            return ScannerResult(
                scanner_name="HTTPScanner",
                target=target_url,
                success=True,
                findings=(
                    ScanFinding(
                        title="Cancellation test finding",
                        severity="low",
                        description="Test finding.",
                        evidence={"test": True},
                        remediation="Test remediation.",
                    ),
                ),
            )

        monkeypatch.setattr(
            scan_service.HTTPScanner,
            "execute",
            scanner_with_cancellation,
        )

        with TestSessionLocal() as db:
            result = scan_service.process_next_scan(
                db,
                heartbeat_session_factory=TestSessionLocal,
            )

            assert result is not None
            assert result.id == scan_id
            assert result.status == "cancelled"

        assert cancellation_observed.is_set()

        with TestSessionLocal() as db:
            cancelled_scan = db.get(Scan, scan_id)

            assert cancelled_scan.status == "cancelled"
            assert cancelled_scan.cancel_requested_at is not None
            assert cancelled_scan.worker_id is None
            assert cancelled_scan.lease_expires_at is None

            findings = (
                db.query(Finding)
                .filter(Finding.scan_id == scan_id)
                .all()
            )

            assert findings == []

    finally:
        Base.metadata.drop_all(bind=engine)
        engine.dispose()