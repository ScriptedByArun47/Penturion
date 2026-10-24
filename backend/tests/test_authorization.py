import pytest
from fastapi.testclient import TestClient

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.core.database import Base, get_db

from app.core.security import create_access_token
from app.models.user import User


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
def auth_client(client, reviewer_token):
    token, _ = reviewer_token
    client.headers.update(
        {"Authorization": f"Bearer {token}"}
    )
    return client


@pytest.fixture
def reviewer_token(client):
    from app.core.database import get_db

    db_generator = app.dependency_overrides[get_db]()
    db = next(db_generator)

    try:
        reviewer = User(
            email="reviewer@example.com",
            password_hash="test-only-not-a-real-password-hash",
            role="reviewer",
            is_active=True,
        )

        db.add(reviewer)
        db.commit()
        db.refresh(reviewer)

        token = create_access_token(reviewer.id)
        return token, reviewer.id
    finally:
        db_generator.close()


@pytest.fixture
def second_auth_client(client):
    from app.core.database import get_db

    db_generator = app.dependency_overrides[get_db]()
    db = next(db_generator)

    try:
        user = User(
            email="seconduser@example.com",
            password_hash="test-only-not-a-real-password-hash",
            role="user",
            is_active=True,
        )

        db.add(user)
        db.commit()
        db.refresh(user)

        token = create_access_token(user.id)
        user_id = user.id
    finally:
        db_generator.close()

    client.headers.update({
        "Authorization": f"Bearer {token}"
    })

    return client, user_id


@pytest.fixture
def target_id(auth_client):
    project_response = auth_client.post(
        "/api/v1/projects",
        json={
            "name": "Authorization Test Project",
            "description": "Automated test",
            "status": "active",
        },
    )

    assert project_response.status_code == 201
    project_id = project_response.json()["id"]

    target_response = auth_client.post(
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
def authorization_request(auth_client, target_id):
    response = auth_client.post(
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
    auth_client,
    target_id,
):
    response = auth_client.post(
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


def test_create_request_for_missing_target(auth_client):
    response = auth_client.post(
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
    auth_client,
    authorization_request,
):
    request_id = authorization_request["id"]

    response = auth_client.get(
        f"/api/v1/authorization-requests/{request_id}"
    )

    assert response.status_code == 200
    assert response.json()["id"] == request_id


def test_list_authorization_requests(
    auth_client,
    authorization_request,
):
    response =auth_client.get(
        "/api/v1/authorization-requests"
    )

    assert response.status_code == 200
    assert len(response.json()) == 1



def test_approve_request_updates_target(
    auth_client,
    authorization_request,
    target_id,
    reviewer_token,
):
    token, reviewer_id = reviewer_token
    request_id = authorization_request["id"]

    review_response = auth_client.patch(
        f"/api/v1/authorization-requests/{request_id}/review",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "status": "approved",
            "review_reason": "Automated workflow test",
        },
    )

    assert review_response.status_code == 200

    reviewed = review_response.json()
    assert reviewed["status"] == "approved"
    assert reviewed["reviewed_by"] == reviewer_id
    assert reviewed["reviewed_at"] is not None

    target_response = auth_client.get(
        f"/api/v1/targets/{target_id}"
    )

    assert target_response.status_code == 200
    assert target_response.json()["authorization_status"] == "approved"



def test_reject_request_updates_target(
   auth_client,
    authorization_request,
    target_id,
    reviewer_token,
):
    token, reviewer_id = reviewer_token
    request_id = authorization_request["id"]

    review_response = auth_client.patch(
        f"/api/v1/authorization-requests/{request_id}/review",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "status": "rejected",
            "review_reason": "Automated rejection test",
        },
    )

    assert review_response.status_code == 200

    reviewed = review_response.json()
    assert reviewed["status"] == "rejected"
    assert reviewed["reviewed_by"] == reviewer_id

    target_response = auth_client.get(
        f"/api/v1/targets/{target_id}"
    )

    assert target_response.json()["authorization_status"] == "rejected"




def test_already_reviewed_request_cannot_be_reviewed_again(
    auth_client,
    authorization_request,
    reviewer_token,
):
    token, _ = reviewer_token
    request_id = authorization_request["id"]
    review_url = (
        f"/api/v1/authorization-requests/{request_id}/review"
    )
    headers = {"Authorization": f"Bearer {token}"}

    first_response = auth_client.patch(
        review_url,
        headers=headers,
        json={
            "status": "approved",
            "review_reason": "First review",
        },
    )

    assert first_response.status_code == 200

    second_response = auth_client.patch(
        review_url,
        headers=headers,
        json={
            "status": "rejected",
            "review_reason": "Second review",
        },
    )

    assert second_response.status_code == 409
    
    
def test_requester_identity_cannot_be_spoofed(
    auth_client,
    target_id,
):
    response = auth_client.post(
        "/api/v1/authorization-requests",
        json={
            "target_id": target_id,
            "evidence_reference": "identity-test",
            "requested_scope": "example.com web testing",
            "requested_by": "victim@example.com",
        },
    )

    assert response.status_code == 201

    # The authenticated user's identity must be used,
    # not the identity submitted in the request body.
    assert response.json()["requested_by"] == "reviewer@example.com"


def test_user_cannot_list_another_users_requests(
    auth_client,
    authorization_request,
    second_auth_client,
):
    second_client, _ = second_auth_client

    response = second_client.get(
        "/api/v1/authorization-requests"
    )

    assert response.status_code == 200
    assert all(
        item["id"] != authorization_request["id"]
        for item in response.json()
    )


def test_user_cannot_get_another_users_request(
    auth_client,
    authorization_request,
    second_auth_client,
):
    second_client, _ = second_auth_client

    response = second_client.get(
        f"/api/v1/authorization-requests/"
        f"{authorization_request['id']}"
    )

    assert response.status_code == 404