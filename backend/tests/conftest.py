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

    client.headers.update({"Authorization": f"Bearer {token}"})
    return client


@pytest.fixture
def second_auth_client(client):
    db_generator = app.dependency_overrides[get_db]()
    db = next(db_generator)

    try:
        user = User(
            email="second-target-user@example.com",
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
    second_client.headers.update({"Authorization": f"Bearer {token}"})
    return second_client


@pytest.fixture
def project_id(auth_client):
    response = auth_client.post(
        "/api/v1/projects",
        json={
            "name": "Test Project",
            "description": "Project for automated tests",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


@pytest.fixture
def target_id(auth_client, project_id):
    response = auth_client.post(
        f"/api/v1/projects/{project_id}/targets",
        json={
            "value": "scan-test.example.com",
            "target_type": "domain",
            "notes": "Authorization gate test",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]