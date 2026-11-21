import pytest

from app.core.database import get_db
from app.models.target import Target
from app.models.scan import Scan
from fastapi.testclient import TestClient

from app.main import app


def test_create_scan_requires_approved_target(auth_client, target_id):
    from tests.test_scan_lifecycle import (
        create_approved_authorization,
    )

    authorization_request_id = create_approved_authorization(
        auth_client,
        target_id,
    )

    # A genuinely pending request must not authorize a scan.
    db_generator = auth_client.app.dependency_overrides[get_db]()
    db = next(db_generator)

    try:
        target = db.get(Target, target_id)
        assert target is not None

        target.authorization_status = "pending"
        db.commit()
    finally:
        db_generator.close()

    response = auth_client.post(
        "/api/v1/scans",
        json={
            "target_id": target_id,
            "authorization_request_id": authorization_request_id,
            "scan_type": "web",
        },
    )

    assert response.status_code == 403
    assert "approved" in response.json()["detail"].lower()


def test_create_scan_for_approved_target(auth_client, target_id):
    from tests.test_scan_lifecycle import (
        create_approved_authorization,
    )

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

    data = response.json()
    assert data["target_id"] == target_id
    assert data["status"] == "queued"
    assert data["scan_type"] == "web"


def test_create_scan_rejects_unsupported_type(auth_client, target_id):
    response = auth_client.post(
        "/api/v1/scans",
        json={
            "target_id": target_id,
            "scan_type": "network",
        },
    )

    assert response.status_code == 422


def test_create_scan_requires_authentication(client, target_id):
    # Create a separate client without authentication headers.
    with TestClient(app) as anonymous_client:
        response = anonymous_client.post(
            "/api/v1/scans",
            json={
                "target_id": target_id,
                "scan_type": "web",
            },
        )

    assert response.status_code == 401


def test_cancel_queued_scan_endpoint(auth_client, target_id):
    from tests.test_scan_lifecycle import create_queued_scan

    scan_id = create_queued_scan(auth_client, target_id)

    response = auth_client.post(
        f"/api/v1/scans/{scan_id}/cancel"
    )

    assert response.status_code == 200, response.text

    data = response.json()
    assert data["status"] == "cancelled"
    assert data["cancel_requested_at"] is not None
    assert data["completed_at"] is not None


def test_cancel_running_scan_endpoint(auth_client, target_id):
    from tests.test_scan_lifecycle import (
        create_queued_scan,
        get_test_db,
        get_user_id,
    )
    from app.services.scan_service import claim_next_scan

    scan_id = create_queued_scan(auth_client, target_id)

    db_generator, db = get_test_db(auth_client)
    try:
        running = claim_next_scan(db, worker_id="api-test-worker")
        assert running is not None
        assert running.id == scan_id
    finally:
        db_generator.close()

    response = auth_client.post(
        f"/api/v1/scans/{scan_id}/cancel"
    )

    assert response.status_code == 200, response.text

    data = response.json()
    assert data["status"] == "running"
    assert data["cancel_requested_at"] is not None


def test_user_cannot_cancel_another_users_scan(
    auth_client, second_auth_client, target_id
):
    from tests.test_scan_lifecycle import create_queued_scan

    scan_id = create_queued_scan(auth_client, target_id)

    response = second_auth_client.post(
        f"/api/v1/scans/{scan_id}/cancel"
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Scan not found"


@pytest.mark.parametrize("terminal_status", ["completed", "failed"])
def test_terminal_scan_cancellation_returns_conflict(
    auth_client, target_id, terminal_status
):
    from tests.test_scan_lifecycle import (
        create_queued_scan,
        get_test_db,
        get_user_id,
    )
    from app.services.scan_service import transition_scan

    scan_id = create_queued_scan(auth_client, target_id)
    owner_id = get_user_id(
        auth_client, "targets-reviewer@example.com"
    )

    db_generator, db = get_test_db(auth_client)
    try:
        transition_scan(db, scan_id, owner_id, "running")

        if terminal_status == "failed":
            transition_scan(
                db,
                scan_id,
                owner_id,
                "failed",
                error_message="Test failure",
            )
        else:
            transition_scan(
                db, scan_id, owner_id, "completed"
            )
    finally:
        db_generator.close()

    response = auth_client.post(
        f"/api/v1/scans/{scan_id}/cancel"
    )

    assert response.status_code == 409
    assert "cannot cancel" in response.json()["detail"].lower()


def test_cancel_nonexistent_scan_returns_404(auth_client):
    response = auth_client.post(
        "/api/v1/scans/00000000-0000-0000-0000-000000000000/cancel"
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Scan not found"


def test_repeated_cancel_endpoint_is_idempotent(auth_client, target_id):
    from tests.test_scan_lifecycle import create_queued_scan

    scan_id = create_queued_scan(auth_client, target_id)
    endpoint = f"/api/v1/scans/{scan_id}/cancel"

    first = auth_client.post(endpoint)
    second = auth_client.post(endpoint)

    assert first.status_code == 200
    assert second.status_code == 200

    assert first.json()["status"] == "cancelled"
    assert second.json()["status"] == "cancelled"

    assert (
        first.json()["cancel_requested_at"]
        == second.json()["cancel_requested_at"]
    )