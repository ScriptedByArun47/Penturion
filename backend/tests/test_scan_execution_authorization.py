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