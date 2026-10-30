
import pytest

import json

from app.models.authorization import AuthorizationRequest
from app.core.database import get_db
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User
from app.services.scan_service import (
    ScanLifecycleError,
    transition_scan,
)


def get_test_db(client):
    """Open a test database session."""
    db_generator = client.app.dependency_overrides[get_db]()
    db = next(db_generator)
    return db_generator, db


def get_user_id(client, email):
    """Find a test user's ID by email."""
    db_generator, db = get_test_db(client)
    try:
        user = db.query(User).filter(User.email == email).first()
        assert user is not None
        return user.id
    finally:
        db_generator.close()


def create_approved_authorization(auth_client, target_id):
    """Create and approve an authorization request for the target."""

    db_generator, db = get_test_db(auth_client)

    try:
        target = db.get(Target, target_id)
        assert target is not None

        target_value = target.value
        owner_id = target.project.owner_id
    finally:
        db_generator.close()

    response = auth_client.post(
        "/api/v1/authorization-requests",
        json={
            "target_id": target_id,
            "evidence_reference": "test-scan-authorization",
            "requested_scope": json.dumps([target_value]),
            "requested_by": "test-requester",
        },
    )

    assert response.status_code in (200, 201), response.text

    authorization_request = response.json()
    request_id = authorization_request["id"]

    review_response = auth_client.patch(
        f"/api/v1/authorization-requests/{request_id}/review",
        json={
            "status": "approved",
            "review_reason": "Approved for automated testing",
        },
    )

    assert review_response.status_code == 200, review_response.text
    assert review_response.json()["status"] == "approved"

    return request_id


def create_queued_scan(auth_client, target_id):
    """Create a queued scan with an approved authorization request."""

    authorization_request_id = create_approved_authorization(
        auth_client,
        target_id,
    )

    response = auth_client.post(
        "/api/v1/scans",
        json={
            "target_id": target_id,
            "authorization_request_id": authorization_request_id,
            "scan_type": "web",
        },
    )

    assert response.status_code == 201, response.text
    assert response.json()["status"] == "queued"
    assert (
        response.json()["target_id"] == target_id
    )

    return response.json()["id"]

def test_queued_scan_can_start(auth_client, target_id):
    scan_id = create_queued_scan(auth_client, target_id)
    owner_id = get_user_id(
        auth_client, "targets-reviewer@example.com"
    )

    db_generator, db = get_test_db(auth_client)
    try:
        scan = transition_scan(
            db, scan_id, owner_id, "running"
        )

        assert scan is not None
        assert scan.status == "running"
        assert scan.started_at is not None
        assert scan.completed_at is None
        assert scan.error_message is None
    finally:
        db_generator.close()


def test_running_scan_can_complete(auth_client, target_id):
    scan_id = create_queued_scan(auth_client, target_id)
    owner_id = get_user_id(
        auth_client, "targets-reviewer@example.com"
    )

    db_generator, db = get_test_db(auth_client)
    try:
        running = transition_scan(
            db, scan_id, owner_id, "running"
        )
        assert running is not None

        completed = transition_scan(
            db, scan_id, owner_id, "completed"
        )

        assert completed is not None
        assert completed.status == "completed"
        assert completed.started_at is not None
        assert completed.completed_at is not None
        assert completed.completed_at >= completed.started_at
        assert completed.error_message is None
    finally:
        db_generator.close()


def test_running_scan_can_fail(auth_client, target_id):
    scan_id = create_queued_scan(auth_client, target_id)
    owner_id = get_user_id(
        auth_client, "targets-reviewer@example.com"
    )

    db_generator, db = get_test_db(auth_client)
    try:
        transition_scan(db, scan_id, owner_id, "running")

        failed = transition_scan(
            db,
            scan_id,
            owner_id,
            "failed",
            error_message=" Scanner timed out ",
        )

        assert failed is not None
        assert failed.status == "failed"
        assert failed.error_message == "Scanner timed out"
        assert failed.started_at is not None
        assert failed.completed_at is not None
    finally:
        db_generator.close()


def test_failure_requires_error_message(auth_client, target_id):
    scan_id = create_queued_scan(auth_client, target_id)
    owner_id = get_user_id(
        auth_client, "targets-reviewer@example.com"
    )

    db_generator, db = get_test_db(auth_client)
    try:
        with pytest.raises(
            ScanLifecycleError,
            match="error message is required",
        ):
            transition_scan(
                db,
                scan_id,
                owner_id,
                "failed",
                error_message="   ",
            )

        scan = db.get(Scan, scan_id)
        assert scan is not None
        assert scan.status == "queued"
        assert scan.completed_at is None
    finally:
        db_generator.close()


def test_completed_scan_cannot_restart(auth_client, target_id):
    scan_id = create_queued_scan(auth_client, target_id)
    owner_id = get_user_id(
        auth_client, "targets-reviewer@example.com"
    )

    db_generator, db = get_test_db(auth_client)
    try:
        transition_scan(db, scan_id, owner_id, "running")
        transition_scan(db, scan_id, owner_id, "completed")

        with pytest.raises(
            ScanLifecycleError,
            match="Cannot transition scan",
        ):
            transition_scan(
                db, scan_id, owner_id, "running"
            )
    finally:
        db_generator.close()


def test_unsupported_status_is_rejected(auth_client, target_id):
    scan_id = create_queued_scan(auth_client, target_id)
    owner_id = get_user_id(
        auth_client, "targets-reviewer@example.com"
    )

    db_generator, db = get_test_db(auth_client)
    try:
        with pytest.raises(
            ScanLifecycleError,
            match="Unsupported scan status",
        ):
            transition_scan(
                db, scan_id, owner_id, "cancelled"
            )
    finally:
        db_generator.close()


def test_user_cannot_transition_another_users_scan(
    auth_client, second_auth_client, target_id
):
    scan_id = create_queued_scan(auth_client, target_id)
    other_user_id = get_user_id(
        second_auth_client, "second-target-user@example.com"
    )

    db_generator, db = get_test_db(second_auth_client)
    try:
        result = transition_scan(
            db, scan_id, other_user_id, "running"
        )
        assert result is None

        scan = db.get(Scan, scan_id)
        assert scan is not None
        assert scan.status == "queued"
    finally:
        db_generator.close()


def test_stale_transition_cannot_overwrite_current_status(
    auth_client, target_id
):
    from sqlalchemy import update

    scan_id = create_queued_scan(auth_client, target_id)
    owner_id = get_user_id(
        auth_client, "targets-reviewer@example.com"
    )

    db_generator, db = get_test_db(auth_client)

    try:
        # Simulate another worker changing the status after
        # the first worker has read the scan as queued.
        db.execute(
            update(Scan)
            .where(
                Scan.id == scan_id,
                Scan.status == "queued",
            )
            .values(status="running")
        )
        db.commit()

        # A stale attempt to start the scan must be rejected:
        # the database status is no longer queued.
        with pytest.raises(
            ScanLifecycleError,
            match="Cannot transition scan",
        ):
            transition_scan(
                db, scan_id, owner_id, "running"
            )

        db.rollback()

        current_scan = db.get(Scan, scan_id)
        assert current_scan is not None
        assert current_scan.status == "running"

    finally:
        db_generator.close()
