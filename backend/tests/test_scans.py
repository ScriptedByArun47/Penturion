import pytest

from app.core.database import get_db
from app.models.target import Target
from app.models.scan import Scan
from fastapi.testclient import TestClient

from app.main import app


def test_create_scan_requires_approved_target(auth_client, target_id):
    db_generator = auth_client.app.dependency_overrides[get_db]()
    db = next(db_generator)

    try:
        target = db.get(Target, target_id)
        assert target is not None
        assert target.authorization_status == "pending"
    finally:
        db_generator.close()

    response = auth_client.post(
        "/api/v1/scans",
        json={
            "target_id": target_id,
            "scan_type": "web",
        },
    )

    assert response.status_code == 403
    assert "approved" in response.json()["detail"].lower()


def test_create_scan_for_approved_target(auth_client, target_id):
    db_generator = auth_client.app.dependency_overrides[get_db]()
    db = next(db_generator)

    try:
        target = db.get(Target, target_id)
        assert target is not None

        target.authorization_status = "approved"
        db.commit()
    finally:
        db_generator.close()

    response = auth_client.post(
        "/api/v1/scans",
        json={
            "target_id": target_id,
            "scan_type": "web",
        },
    )

    assert response.status_code == 201

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