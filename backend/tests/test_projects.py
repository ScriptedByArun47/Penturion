import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.core.database import Base, get_db
from app.models import Project, Target
from app.core.security import create_access_token
from app.models.user import User


@pytest.fixture
def client():
    # An isolated in-memory SQLite database for each test.
    test_engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    TestingSessionLocal = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=test_engine,
    )

    Base.metadata.create_all(bind=test_engine)

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
    Base.metadata.drop_all(bind=test_engine)
    test_engine.dispose()

@pytest.fixture
def auth_client(client):
    from app.core.database import get_db

    db_generator = app.dependency_overrides[get_db]()
    db = next(db_generator)

    try:
        user = User(
            email="projects-reviewer@example.com",
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
def second_auth_client(client):
    from app.core.database import get_db

    db_generator = app.dependency_overrides[get_db]()
    db = next(db_generator)

    try:
        user = User(
            email="second-user@example.com",
            password_hash="test-only-placeholder",
            role="user",
            is_active=True,
        )

        db.add(user)
        db.commit()
        db.refresh(user)

        token = create_access_token(user.id)
    finally:
        db_generator.close()

    second_client = TestClient(app)
    second_client.headers.update(
        {"Authorization": f"Bearer {token}"}
    )
    return second_client


def test_health_check(client):
    response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_list_projects_empty(auth_client):
    response = auth_client.get("/api/v1/projects")

    assert response.status_code == 200
    assert response.json() == []


def test_create_and_retrieve_project(auth_client):
    create_response = auth_client.post(
        "/api/v1/projects",
        json={
            "name": "Automated Test Project",
            "description": "Testing with an isolated database",
        },
    )

    assert create_response.status_code == 201

    project = create_response.json()
    assert project["name"] == "Automated Test Project"
    assert project["status"] == "active"

    project_id = project["id"]

    get_response = auth_client.get(f"/api/v1/projects/{project_id}")

    assert get_response.status_code == 200
    assert get_response.json()["id"] == project_id


def test_get_nonexistent_project(auth_client):
    response = auth_client.get(
        "/api/v1/projects/00000000-0000-0000-0000-000000000000"
    )

    assert response.status_code == 404


def test_create_project_without_name(auth_client):
    response = auth_client.post(
        "/api/v1/projects",
        json={"description": "Missing project name"},
    )

    assert response.status_code == 422
    
def test_update_project(auth_client):
    create_response = auth_client.post(
        "/api/v1/projects",
        json={
            "name": "Original Project",
            "description": "Before update",
        },
    )

    assert create_response.status_code == 201
    project_id = create_response.json()["id"]

    update_response = auth_client.patch(
        f"/api/v1/projects/{project_id}",
        json={
            "name": "Updated Project",
            "description": "After update",
        },
    )

    assert update_response.status_code == 200
    assert update_response.json()["name"] == "Updated Project"
    assert update_response.json()["description"] == "After update"


def test_delete_project(auth_client):
    create_response = auth_client.post(
        "/api/v1/projects",
        json={
            "name": "Project To Delete",
            "description": "Delete endpoint test",
        },
    )

    assert create_response.status_code == 201
    project_id = create_response.json()["id"]

    delete_response = auth_client.delete(
        f"/api/v1/projects/{project_id}"
    )

    assert delete_response.status_code == 204

    get_response = auth_client.get(
        f"/api/v1/projects/{project_id}"
    )

    assert get_response.status_code == 404

def test_user_cannot_view_another_users_project(auth_client, second_auth_client):
    create_response = auth_client.post(
        "/api/v1/projects",
        json={"name": "Private Project"},
    )
    assert create_response.status_code == 201
    project_id = create_response.json()["id"]

    response = second_auth_client.get(
        f"/api/v1/projects/{project_id}"
    )
    assert response.status_code == 404


def test_user_cannot_update_another_users_project(auth_client, second_auth_client):
    create_response = auth_client.post(
        "/api/v1/projects",
        json={"name": "Private Project"},
    )
    assert create_response.status_code == 201
    project_id = create_response.json()["id"]

    response = second_auth_client.patch(
        f"/api/v1/projects/{project_id}",
        json={"name": "Unauthorized Update"},
    )
    assert response.status_code == 404

    owner_response = auth_client.get(
        f"/api/v1/projects/{project_id}"
    )
    assert owner_response.status_code == 200
    assert owner_response.json()["name"] == "Private Project"


def test_user_cannot_delete_another_users_project(auth_client, second_auth_client):
    create_response = auth_client.post(
        "/api/v1/projects",
        json={"name": "Private Project"},
    )
    assert create_response.status_code == 201
    project_id = create_response.json()["id"]

    response = second_auth_client.delete(
        f"/api/v1/projects/{project_id}"
    )
    assert response.status_code == 404

    owner_response = auth_client.get(
        f"/api/v1/projects/{project_id}"
    )
    assert owner_response.status_code == 200


def test_user_lists_only_their_own_projects(auth_client, second_auth_client):
    auth_client.post(
        "/api/v1/projects",
        json={"name": "User One Project"},
    )
    second_auth_client.post(
        "/api/v1/projects",
        json={"name": "User Two Project"},
    )

    first_projects = auth_client.get("/api/v1/projects")
    second_projects = second_auth_client.get("/api/v1/projects")

    assert first_projects.status_code == 200
    assert second_projects.status_code == 200

    assert [p["name"] for p in first_projects.json()] == [
        "User One Project"
    ]
    assert [p["name"] for p in second_projects.json()] == [
        "User Two Project"
    ]