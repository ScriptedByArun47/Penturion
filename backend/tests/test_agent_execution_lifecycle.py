import pytest

from app.core.database import get_db
from app.models.agent_execution import AgentExecution
from app.models.scan import Scan
from app.models.user import User

from app.services.agent_execution_service import (
    AgentExecutionLifecycleError,
    create_agent_execution,
    start_agent_execution,
    complete_agent_execution,
    fail_agent_execution,
    skip_agent_execution,
    retry_agent_execution,
)


def get_test_db(client):
    generator = client.app.dependency_overrides[get_db]()
    db = next(generator)
    return generator, db


def create_test_scan(client, target_id):
    """Create a scan record for lifecycle testing."""

    generator, db = get_test_db(client)

    try:
        user = db.query(User).filter(
            User.email == "targets-reviewer@example.com"
        ).first()

        assert user is not None

        scan = Scan(
            target_id=target_id,
            requested_by=user.id,
            status="queued",
            scan_type="web",
        )

        db.add(scan)
        db.commit()
        db.refresh(scan)

        return scan.id

    finally:
        generator.close()


def test_create_agent_execution(auth_client, target_id):
    scan_id = create_test_scan(auth_client, target_id)

    generator, db = get_test_db(auth_client)

    try:
        execution = create_agent_execution(
            db,
            scan_id,
            "A01",
            "Subdomain Discovery",
        )

        assert execution.status == "pending"
        assert execution.attempt_number == 1
        assert execution.agent_id == "A01"
        assert execution.metadata_json == {}

    finally:
        generator.close()


def test_agent_execution_can_complete(auth_client, target_id):
    scan_id = create_test_scan(auth_client, target_id)

    generator, db = get_test_db(auth_client)

    try:
        execution = create_agent_execution(
            db, scan_id, "A01", "Subdomain Discovery"
        )

        execution = start_agent_execution(db, execution.id)

        assert execution.status == "running"

        execution = complete_agent_execution(
            db,
            execution.id,
            findings_count=2,
            assets_discovered=15,
        )

        assert execution.status == "completed"
        assert execution.findings_count == 2
        assert execution.assets_discovered == 15
        assert execution.completed_at is not None
        assert execution.duration_ms >= 0

    finally:
        generator.close()


def test_failed_execution_can_be_retried(
    auth_client, target_id
):
    scan_id = create_test_scan(auth_client, target_id)

    generator, db = get_test_db(auth_client)

    try:
        first = create_agent_execution(
            db, scan_id, "A01", "Subdomain Discovery"
        )

        start_agent_execution(db, first.id)

        failed = fail_agent_execution(
            db,
            first.id,
            "Temporary DNS resolution failure",
        )

        assert failed.status == "failed"

        second = retry_agent_execution(
            db,
            scan_id,
            "A01",
        )

        assert second.status == "pending"
        assert second.attempt_number == 2

        # Previous attempt must remain unchanged.
        previous = db.get(AgentExecution, first.id)

        assert previous.status == "failed"
        assert previous.attempt_number == 1

    finally:
        generator.close()


def test_agent_execution_can_be_skipped(
    auth_client, target_id
):
    scan_id = create_test_scan(auth_client, target_id)

    generator, db = get_test_db(auth_client)

    try:
        execution = create_agent_execution(
            db, scan_id, "A02", "DNS Enumeration"
        )

        skipped = skip_agent_execution(
            db,
            execution.id,
            "Dependency unavailable",
        )

        assert skipped.status == "skipped"
        assert skipped.completed_at is not None

    finally:
        generator.close()


def test_completed_execution_cannot_restart(
    auth_client, target_id
):
    scan_id = create_test_scan(auth_client, target_id)

    generator, db = get_test_db(auth_client)

    try:
        execution = create_agent_execution(
            db, scan_id, "A01", "Subdomain Discovery"
        )

        start_agent_execution(db, execution.id)
        complete_agent_execution(db, execution.id)

        with pytest.raises(AgentExecutionLifecycleError):
            start_agent_execution(db, execution.id)

    finally:
        generator.close()


def test_duplicate_initial_execution_is_rejected(
    auth_client, target_id
):
    scan_id = create_test_scan(auth_client, target_id)

    generator, db = get_test_db(auth_client)

    try:
        create_agent_execution(
            db, scan_id, "A01", "Subdomain Discovery"
        )

        with pytest.raises(AgentExecutionLifecycleError):
            create_agent_execution(
                db, scan_id, "A01", "Subdomain Discovery"
            )

    finally:
        generator.close()


def test_retry_limit_is_enforced(auth_client, target_id):
    scan_id = create_test_scan(auth_client, target_id)

    generator, db = get_test_db(auth_client)

    try:
        first = create_agent_execution(
            db, scan_id, "A01", "Subdomain Discovery"
        )

        start_agent_execution(db, first.id)

        fail_agent_execution(
            db, first.id, "First attempt failed"
        )

        second = retry_agent_execution(
            db, scan_id, "A01", max_attempts=2
        )

        start_agent_execution(db, second.id)

        fail_agent_execution(
            db, second.id, "Second attempt failed"
        )

        with pytest.raises(AgentExecutionLifecycleError):
            retry_agent_execution(
                db, scan_id, "A01", max_attempts=2
            )

    finally:
        generator.close()