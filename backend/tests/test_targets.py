"""Tests for target management and scan authorization."""

import pytest
from sqlalchemy import select

from app.models.scan import Scan
from app.services.scan_service import (
    ScanAuthorizationError,
    create_scan,
    validate_scan_authorization,
)


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

def test_user_cannot_create_target_in_another_users_project(
    auth_client, second_auth_client, project_id
):
    response = second_auth_client.post(
        f"/api/v1/projects/{project_id}/targets",
        json={
            "value": "example.com",
            "target_type": "domain",
        },
    )

    assert response.status_code == 404


def test_user_cannot_list_another_users_project_targets(
    auth_client, second_auth_client, project_id
):
    create_response = auth_client.post(
        f"/api/v1/projects/{project_id}/targets",
        json={
            "value": "example.com",
            "target_type": "domain",
        },
    )
    assert create_response.status_code == 201

    response = second_auth_client.get(
        f"/api/v1/projects/{project_id}/targets"
    )

    assert response.status_code == 404


def test_user_cannot_read_another_users_target(
    auth_client, second_auth_client, project_id
):
    create_response = auth_client.post(
        f"/api/v1/projects/{project_id}/targets",
        json={
            "value": "example.com",
            "target_type": "domain",
        },
    )
    assert create_response.status_code == 201
    target_id = create_response.json()["id"]

    response = second_auth_client.get(
        f"/api/v1/targets/{target_id}"
    )

    assert response.status_code == 404


def test_user_cannot_update_or_delete_another_users_target(
    auth_client, second_auth_client, project_id
):
    create_response = auth_client.post(
        f"/api/v1/projects/{project_id}/targets",
        json={
            "value": "example.com",
            "target_type": "domain",
        },
    )
    assert create_response.status_code == 201
    target_id = create_response.json()["id"]

    update_response = second_auth_client.patch(
        f"/api/v1/targets/{target_id}",
        json={"notes": "Unauthorized modification"},
    )
    assert update_response.status_code == 404

    delete_response = second_auth_client.delete(
        f"/api/v1/targets/{target_id}"
    )
    assert delete_response.status_code == 404

    owner_response = auth_client.get(
        f"/api/v1/targets/{target_id}"
    )
    assert owner_response.status_code == 200
    assert owner_response.json()["notes"] is None


def test_pending_target_cannot_be_scanned(
    auth_client,
    target_id,
):
    from app.core.database import get_db
    from app.models.target import Target

    db_generator = auth_client.app.dependency_overrides[get_db]()
    db = next(db_generator)

    try:
        target = db.get(Target, target_id)
        assert target is not None
        assert target.authorization_status == "pending"

        with pytest.raises(ScanAuthorizationError):
            validate_scan_authorization(
                db=db,
                target_id=target_id,
                owner_id=target.project.owner_id,
            )
    finally:
        db_generator.close()



def test_approved_target_passes_scan_authorization(
    auth_client,
    target_id,
):
    from app.core.database import get_db
    from app.models.target import Target

    db_generator = auth_client.app.dependency_overrides[get_db]()
    db = next(db_generator)

    try:
        target = db.get(Target, target_id)
        assert target is not None

        target.authorization_status = "approved"
        db.commit()

        result = validate_scan_authorization(
            db=db,
            target_id=target_id,
            owner_id=target.project.owner_id,
        )

        assert result.id == target_id
        assert result.authorization_status == "approved"
    finally:
        db_generator.close()


def test_rejected_target_cannot_be_scanned(
    auth_client,
    target_id,
):
    from app.core.database import get_db
    from app.models.target import Target

    db_generator = auth_client.app.dependency_overrides[get_db]()
    db = next(db_generator)

    try:
        target = db.get(Target, target_id)
        assert target is not None

        target.authorization_status = "rejected"
        db.commit()

        with pytest.raises(ScanAuthorizationError):
            validate_scan_authorization(
                db=db,
                target_id=target_id,
                owner_id=target.project.owner_id,
            )
    finally:
        db_generator.close()
        
        


def test_user_cannot_scan_another_users_target(
    auth_client,
    target_id,
    second_auth_client,
):
    from app.core.database import get_db
    from app.models.target import Target
    from app.services.scan_service import (
        validate_scan_authorization,
        ScanAuthorizationError,
    )

    db_generator = auth_client.app.dependency_overrides[get_db]()
    db = next(db_generator)

    try:
        target = db.get(Target, target_id)
        assert target is not None

        # Even an approved target must remain inaccessible
        # to a user who does not own its project.
        target.authorization_status = "approved"
        db.commit()

        with pytest.raises(ScanAuthorizationError):
            validate_scan_authorization(
                db=db,
                target_id=target_id,
                owner_id="another-users-id",
            )
    finally:
        db_generator.close()

def test_create_scan_rejects_unsupported_scan_type(
    auth_client, target_id
):
    from app.core.database import get_db
    from app.models.target import Target

    db_generator = auth_client.app.dependency_overrides[get_db]()
    db = next(db_generator)

    try:
        target = db.get(Target, target_id)
        assert target is not None

        with pytest.raises(ValueError, match="Unsupported scan type"):
            create_scan(
                db=db,
                target_id=target_id,
                owner_id=target.project.owner_id,
                scan_type="network",
            )

        # An unsupported scan type must not create a scan record.
        scans = db.scalars(
            select(Scan).where(Scan.target_id == target_id)
        ).all()
        assert scans == []
    finally:
        db_generator.close()
        
def test_approved_target_creates_queued_scan(
    auth_client, target_id
):
    from app.core.database import get_db
    from app.models.target import Target

    db_generator = auth_client.app.dependency_overrides[get_db]()
    db = next(db_generator)

    try:
        target = db.get(Target, target_id)
        assert target is not None

        target.authorization_status = "approved"
        db.commit()

        scan = create_scan(
            db=db,
            target_id=target_id,
            owner_id=target.project.owner_id,
            scan_type="web",
        )

        assert scan.id is not None
        assert scan.target_id == target_id
        assert scan.status == "queued"
        assert scan.scan_type == "web"
        assert scan.requested_by == target.project.owner_id
    finally:
        db_generator.close()


def test_changing_approved_target_resets_authorization(
    auth_client,
    target_id,
):
    from app.core.database import get_db
    from app.models.target import Target

    db_generator = auth_client.app.dependency_overrides[get_db]()
    db = next(db_generator)

    try:
        target = db.get(Target, target_id)
        assert target is not None

        target.authorization_status = "approved"
        db.commit()
    finally:
        db_generator.close()

    response = auth_client.patch(
        f"/api/v1/targets/{target_id}",
        json={"value": "another-domain.com"},
    )

    assert response.status_code == 200
    assert response.json()["value"] == "another-domain.com"
    assert response.json()["authorization_status"] == "pending"


def test_updating_notes_preserves_target_authorization(
    auth_client,
    target_id,
):
    from app.core.database import get_db
    from app.models.target import Target

    db_generator = auth_client.app.dependency_overrides[get_db]()
    db = next(db_generator)

    try:
        target = db.get(Target, target_id)
        assert target is not None

        target.authorization_status = "approved"
        db.commit()
    finally:
        db_generator.close()

    response = auth_client.patch(
        f"/api/v1/targets/{target_id}",
        json={"notes": "Updated notes"},
    )

    assert response.status_code == 200
    assert response.json()["authorization_status"] == "approved"
    assert response.json()["notes"] == "Updated notes"
