import pytest

from app.core.database import get_db
from app.models.target import Target
from app.services.scan_service import (
    ScanAuthorizationError,
    claim_next_scan,
    validate_scan_for_execution,
)

from tests.test_scan_lifecycle import (
    create_queued_scan,
    get_test_db,
)
from datetime import datetime, timedelta, timezone

from app.models.authorization import AuthorizationRequest


def test_approved_target_passes_execution_check(
    auth_client, target_id
):
    scan_id = create_queued_scan(auth_client, target_id)

    db_generator, db = get_test_db(auth_client)

    try:
        claimed = claim_next_scan(db)
        assert claimed is not None
        assert claimed.id == scan_id

        scan = validate_scan_for_execution(db, scan_id)

        assert scan is not None
        assert scan.status == "running"
        assert scan.target.authorization_status == "approved"
    finally:
        db_generator.close()


def test_revoked_authorization_blocks_execution(
    auth_client, target_id
):
    scan_id = create_queued_scan(auth_client, target_id)

    db_generator, db = get_test_db(auth_client)

    try:
        claimed = claim_next_scan(db)
        assert claimed is not None

        target = db.get(Target, target_id)
        assert target is not None

        target.authorization_status = "revoked"
        db.commit()

        with pytest.raises(
            ScanAuthorizationError,
            match="no longer approved",
        ):
            validate_scan_for_execution(db, scan_id)
    finally:
        db_generator.close()
        

def test_expired_authorization_blocks_execution(
    auth_client, target_id
):
    scan_id = create_queued_scan(auth_client, target_id)

    db_generator, db = get_test_db(auth_client)

    try:
        claimed = claim_next_scan(db)
        assert claimed is not None
        assert claimed.id == scan_id

        scan = db.get(
            __import__("app.models.scan", fromlist=["Scan"]).Scan,
            scan_id,
        )
        assert scan is not None

        authorization = db.get(
            AuthorizationRequest,
            scan.authorization_request_id,
        )
        assert authorization is not None

        authorization.expires_at = (
            datetime.now(timezone.utc) - timedelta(days=1)
        )
        db.commit()

        with pytest.raises(
            ScanAuthorizationError,
            match="Authorization has expired",
        ):
            validate_scan_for_execution(db, scan_id)

    finally:
        db_generator.close()
        
def test_narrow_domain_scope_passes_execution_authorization(
    auth_client, target_id
):
    import json
    from app.models.scan import Scan

    scan_id = create_queued_scan(auth_client, target_id)

    db_generator, db = get_test_db(auth_client)

    try:
        claimed = claim_next_scan(db)
        assert claimed is not None
        assert claimed.id == scan_id

        scan = db.get(Scan, scan_id)
        assert scan is not None

        root_domain = scan.target.value
        narrow_scope = f"api.{root_domain}"

        scan.authorization_request.requested_scope = json.dumps(
            [narrow_scope]
        )
        db.commit()

        validated = validate_scan_for_execution(db, scan_id)

        assert validated is not None
        assert validated.status == "running"

    finally:
        db_generator.close()