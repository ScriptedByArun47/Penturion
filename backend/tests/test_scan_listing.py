from app.core.database import get_db
from app.models.scan import Scan
from app.models.target import Target


def approve_target(auth_client, target_id):
    db_generator = auth_client.app.dependency_overrides[get_db]()
    db = next(db_generator)

    try:
        target = db.get(Target, target_id)
        assert target is not None
        target.authorization_status = "approved"
        db.commit()
    finally:
        db_generator.close()


def test_list_scans_returns_empty_list(auth_client):
    response = auth_client.get("/api/v1/scans")

    assert response.status_code == 200
    assert response.json() == []


def test_list_scans_returns_own_scans(auth_client, target_id):
    approve_target(auth_client, target_id)

    create_response = auth_client.post(
        "/api/v1/scans",
        json={"target_id": target_id, "scan_type": "web"},
    )
    assert create_response.status_code == 201

    response = auth_client.get("/api/v1/scans")

    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["id"] == create_response.json()["id"]


def test_get_scan_details(auth_client, target_id):
    approve_target(auth_client, target_id)

    create_response = auth_client.post(
        "/api/v1/scans",
        json={"target_id": target_id, "scan_type": "web"},
    )
    assert create_response.status_code == 201
    scan_id = create_response.json()["id"]

    response = auth_client.get(f"/api/v1/scans/{scan_id}")

    assert response.status_code == 200
    assert response.json()["id"] == scan_id
    assert response.json()["status"] == "queued"


def test_user_cannot_get_another_users_scan(
    auth_client,
    second_auth_client,
    target_id,
):
    approve_target(auth_client, target_id)

    create_response = auth_client.post(
        "/api/v1/scans",
        json={"target_id": target_id, "scan_type": "web"},
    )
    assert create_response.status_code == 201

    scan_id = create_response.json()["id"]

    response = second_auth_client.get(f"/api/v1/scans/{scan_id}")

    assert response.status_code == 404


def test_list_scans_requires_authentication(client):
    from fastapi.testclient import TestClient
    from app.main import app

    with TestClient(app) as anonymous_client:
        response = anonymous_client.get("/api/v1/scans")

    assert response.status_code == 401