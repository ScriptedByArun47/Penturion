import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.database import get_db, Base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool


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
def project_id(client):
    response = client.post(
        "/api/v1/projects",
        json={
            "name": "Target API Test Project",
            "description": "Automated test",
            "status": "active",
        },
    )

    assert response.status_code == 201
    return response.json()["id"]


def test_create_target(client, project_id):
    response = client.post(
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


def test_create_target_for_missing_project(client):
    response = client.post(
        "/api/v1/projects/nonexistent-project/targets",
        json={
            "value": "example.com",
            "target_type": "domain",
        },
    )

    assert response.status_code == 404


def test_create_target_rejects_empty_value(client, project_id):
    response = client.post(
        f"/api/v1/projects/{project_id}/targets",
        json={
            "value": "   ",
            "target_type": "domain",
        },
    )

    assert response.status_code == 422


def test_create_target_cannot_set_authorization(client, project_id):
    response = client.post(
        f"/api/v1/projects/{project_id}/targets",
        json={
            "value": "example.com",
            "target_type": "domain",
            "authorization_status": "approved",
        },
    )

    assert response.status_code == 201
    assert response.json()["authorization_status"] == "pending"