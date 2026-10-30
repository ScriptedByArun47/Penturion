
import json

from app.core.database import get_db
from app.models.target import Target


def create_approved_authorization(auth_client, target_id):
    db_generator = auth_client.app.dependency_overrides[get_db]()
    db = next(db_generator)

    try:
        target = db.get(Target, target_id)
        assert target is not None
        target_value = target.value
    finally:
        db_generator.close()

    response = auth_client.post(
        "/api/v1/authorization-requests",
        json={
            "target_id": target_id,
            "evidence_reference": "test-scan-listing-authorization",
            "requested_scope": json.dumps([target_value]),
            "requested_by": "test-requester",
        },
    )
    assert response.status_code in (200, 201), response.text

    authorization_request_id = response.json()["id"]

    review_response = auth_client.patch(
        f"/api/v1/authorization-requests/{authorization_request_id}/review",
        json={
            "status": "approved",
            "review_reason": "Approved for scan listing tests",
        },
    )
    assert review_response.status_code == 200, review_response.text

    return authorization_request_id


def create_queued_scan(auth_client, target_id):
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

    return response.json()


def test_list_scans_returns_empty_list(auth_client):
    response = auth_client.get("/api/v1/scans")

    assert response.status_code == 200
    assert response.json() == []


def test_list_scans_returns_own_scans(auth_client, target_id):
    created_scan = create_queued_scan(auth_client, target_id)

    response = auth_client.get("/api/v1/scans")

    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["id"] == created_scan["id"]


def test_get_scan_details(auth_client, target_id):
    created_scan = create_queued_scan(auth_client, target_id)
    scan_id = created_scan["id"]

    response = auth_client.get(f"/api/v1/scans/{scan_id}")

    assert response.status_code == 200
    assert response.json()["id"] == scan_id
    assert response.json()["status"] == "queued"


def test_user_cannot_get_another_users_scan(
    auth_client,
    second_auth_client,
    target_id,
):
    created_scan = create_queued_scan(auth_client, target_id)
    scan_id = created_scan["id"]

    response = second_auth_client.get(f"/api/v1/scans/{scan_id}")

    assert response.status_code == 404


def test_list_scans_requires_authentication(client):
    from fastapi.testclient import TestClient
    from app.main import app

    with TestClient(app) as anonymous_client:
        response = anonymous_client.get("/api/v1/scans")

    assert response.status_code == 401
