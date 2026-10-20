import pytest
from fastapi.testclient import TestClient

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.core.database import Base, get_db


@pytest.fixture
def client():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    TestingSessionLocal = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=engine,
    )

    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture
def target_id(client):
    project_response = client.post(
        "/api/v1/projects",
        json={
            "name": "Authorization Test Project",
            "description": "Automated test",
            "status": "active",
        },
    )

    assert project_response.status_code == 201
    project_id = project_response.json()["id"]

    target_response = client.post(
        f"/api/v1/projects/{project_id}/targets",
        json={
            "value": "example.com",
            "target_type": "domain",
            "notes": "Test target",
        },
    )

    assert target_response.status_code == 201
    return target_response.json()["id"]


@pytest.fixture
def authorization_request(client, target_id):
    response = client.post(
        "/api/v1/authorization-requests",
        json={
            "target_id": target_id,
            "evidence_reference": "test-evidence-001",
            "requested_scope": "example.com web testing",
            "requested_by": "test-requester",
        },
    )

    assert response.status_code == 201
    return response.json()


def test_create_authorization_request(
    client,
    target_id,
):
    response = client.post(
        "/api/v1/authorization-requests",
        json={
            "target_id": target_id,
            "evidence_reference": "test-evidence-002",
            "requested_scope": "example.com web testing",
            "requested_by": "test-requester",
        },
    )

    assert response.status_code == 201

    data = response.json()
    assert data["target_id"] == target_id
    assert data["status"] == "pending"
    assert data["reviewed_by"] is None


def test_create_request_for_missing_target(client):
    response = client.post(
        "/api/v1/authorization-requests",
        json={
            "target_id": "00000000-0000-0000-0000-000000000000",
            "evidence_reference": "test-evidence",
            "requested_scope": "example.com",
            "requested_by": "test-requester",
        },
    )

    assert response.status_code == 404


def test_get_authorization_request(
    client,
    authorization_request,
):
    request_id = authorization_request["id"]

    response = client.get(
        f"/api/v1/authorization-requests/{request_id}"
    )

    assert response.status_code == 200
    assert response.json()["id"] == request_id


def test_list_authorization_requests(
    client,
    authorization_request,
):
    response = client.get(
        "/api/v1/authorization-requests"
    )

    assert response.status_code == 200
    assert len(response.json()) == 1


def test_approve_request_updates_target(
    client,
    authorization_request,
    target_id,
):
    request_id = authorization_request["id"]

    review_response = client.patch(
        f"/api/v1/authorization-requests/{request_id}/review",
        json={
            "status": "approved",
            "reviewed_by": "local-test-reviewer",
            "review_reason": "Automated workflow test",
        },
    )

    assert review_response.status_code == 200

    reviewed = review_response.json()
    assert reviewed["status"] == "approved"
    assert reviewed["reviewed_by"] == "local-test-reviewer"
    assert reviewed["reviewed_at"] is not None

    target_response = client.get(
        f"/api/v1/targets/{target_id}"
    )

    assert target_response.status_code == 200
    assert target_response.json()["authorization_status"] == "approved"


def test_reject_request_updates_target(
    client,
    authorization_request,
    target_id,
):
    request_id = authorization_request["id"]

    review_response = client.patch(
        f"/api/v1/authorization-requests/{request_id}/review",
        json={
            "status": "rejected",
            "reviewed_by": "local-test-reviewer",
            "review_reason": "Automated rejection test",
        },
    )

    assert review_response.status_code == 200
    assert review_response.json()["status"] == "rejected"

    target_response = client.get(
        f"/api/v1/targets/{target_id}"
    )

    assert target_response.json()["authorization_status"] == "rejected"


def test_already_reviewed_request_cannot_be_reviewed_again(
    client,
    authorization_request,
):
    request_id = authorization_request["id"]
    review_url = (
        f"/api/v1/authorization-requests/{request_id}/review"
    )

    first_response = client.patch(
        review_url,
        json={
            "status": "approved",
            "reviewed_by": "local-test-reviewer",
            "review_reason": "First review",
        },
    )

    assert first_response.status_code == 200

    second_response = client.patch(
        review_url,
        json={
            "status": "rejected",
            "reviewed_by": "local-test-reviewer",
            "review_reason": "Second review",
        },
    )

    assert second_response.status_code == 409