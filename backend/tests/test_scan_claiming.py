from app.core.database import get_db
from app.models.scan import Scan
from app.services.scan_service import claim_next_scan

# Reuse the existing test helpers.
from tests.test_scan_lifecycle import (
    create_queued_scan,
    get_test_db,
)


def test_worker_claims_queued_scan(auth_client, target_id):
    scan_id = create_queued_scan(auth_client, target_id)

    db_generator, db = get_test_db(auth_client)

    try:
        claimed = claim_next_scan(db)

        assert claimed is not None
        assert claimed.id == scan_id
        assert claimed.status == "running"
        assert claimed.started_at is not None
        assert claimed.completed_at is None
    finally:
        db_generator.close()


def test_worker_returns_none_when_queue_is_empty(auth_client):
    db_generator, db = get_test_db(auth_client)

    try:
        claimed = claim_next_scan(db)
        assert claimed is None
    finally:
        db_generator.close()


def test_claimed_scan_is_not_claimed_again(auth_client, target_id):
    scan_id = create_queued_scan(auth_client, target_id)

    db_generator, db = get_test_db(auth_client)

    try:
        first_claim = claim_next_scan(db)

        assert first_claim is not None
        assert first_claim.id == scan_id

        second_claim = claim_next_scan(db)

        assert second_claim is None

        scan = db.get(Scan, scan_id)
        assert scan is not None
        assert scan.status == "running"
    finally:
        db_generator.close()