import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.database import get_db, Base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
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
def auth_client(client):
    db_generator = app.dependency_overrides[get_db]()
    db = next(db_generator)

    try:
        user = User(
            email="targets-reviewer@example.com",
            password_hash="test-only-placeholder",
            role="reviewer",
            is_active=True,
        )

        db.add(user)
        db.commit()
        db.refresh(user)

        token = create_access_token(user.id)
    finally:
        db_generator.close()

    client.headers.update(
        {"Authorization": f"Bearer {token}"}
    )
    return client


@pytest.fixture
def project_id(auth_client):
    response = auth_client.post(
        "/api/v1/projects",
        json={
            "name": "Target API Test Project",
            "description": "Automated test",
            "status": "active",
        },
    )

    assert response.status_code == 201
    return response.json()["id"]


def test_create_target(auth_client, project_id):
    response = auth_client.post(
        f"/api/v1/projects/{project_id}/targets",
        json={
            "value": "example.com",
            "target_type": "domain",
            "notes": "Test target",
        },
    )

    assert response.status_code == 201

    data = response.json()
    assert data["value"] == "example.com"
    assert data["target_type"] == "domain"
    assert data["authorization_status"] == "pending"
    assert data["project_id"] == project_id


def test_list_project_targets(client, project_id):
    client.post(
        f"/api/v1/projects/{project_id}/targets",
        json={
            "value": "example.com",
            "target_type": "domain",
        },
    )

    response = client.get(
        f"/api/v1/projects/{project_id}/targets"
    )

    assert response.status_code == 200
    assert len(response.json()) == 1


def test_create_target_for_missing_project(auth_client):
    response = auth_client.post(
        "/api/v1/projects/nonexistent-project/targets",
        json={
            "value": "example.com",
            "target_type": "domain",
        },
    )

    assert response.status_code == 404


def test_create_target_rejects_empty_value(auth_client, project_id):
    response = auth_client.post(
        f"/api/v1/projects/{project_id}/targets",
        json={
            "value": "   ",
            "target_type": "domain",
        },
    )

    assert response.status_code == 422


def test_create_target_cannot_set_authorization(auth_client, project_id):
    response = auth_client.post(
        f"/api/v1/projects/{project_id}/targets",
        json={
            "value": "example.com",
            "target_type": "domain",
            "authorization_status": "approved",
        },
    )

    assert response.status_code == 201
    assert response.json()["authorization_status"] == "pending"