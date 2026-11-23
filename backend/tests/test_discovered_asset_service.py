import pytest

from app.models.discovered_asset import DiscoveredAsset
from app.models.target import Target
from app.models.scan import Scan
from app.services.discovered_asset_service import (
    persist_discovered_assets,
    DiscoveredAssetError,
)

from tests.test_scan_lifecycle import (
    create_queued_scan,
    get_test_db,
)
from app.services.scan_service import claim_next_scan


def prepare_running_scan(auth_client, target_id):
    scan_id = create_queued_scan(auth_client, target_id)
    db_generator, db = get_test_db(auth_client)

    scan = claim_next_scan(db)
    assert scan is not None
    assert scan.id == scan_id

    return scan_id, scan.worker_id, db_generator, db


def test_persists_in_scope_subdomain(auth_client, target_id):
    scan_id, worker_id, generator, db = prepare_running_scan(
        auth_client, target_id
    )

    try:
        target = db.get(Target, target_id)
        hostname = f"api.{target.value}"

        assets = persist_discovered_assets(
            db, scan_id, worker_id, [hostname]
        )

        assert len(assets) == 1
        assert assets[0].value == hostname
        assert assets[0].scope_status == "in_scope"
        assert assets[0].source_agent == "A01"
    finally:
        generator.close()


def test_persists_out_of_scope_hostname(auth_client, target_id):
    scan_id, worker_id, generator, db = prepare_running_scan(
        auth_client, target_id
    )

    try:
        scan = db.get(Scan, scan_id)
        target = db.get(Target, target_id)

        # Only api.<root> is approved; dev.<root> must remain out of scope.
        scan.authorization_request.requested_scope = (
            f'["api.{target.value}"]'
        )
        hostname = f"dev.{target.value}"

        assets = persist_discovered_assets(
            db, scan_id, worker_id, [hostname]
        )

        assert len(assets) == 1
        assert assets[0].value == hostname
        assert assets[0].scope_status == "out_of_scope"
    finally:
        generator.close()

def test_duplicate_discoveries_are_deduplicated(
    auth_client, target_id
):
    scan_id, worker_id, generator, db = prepare_running_scan(
        auth_client, target_id
    )

    try:
        target = db.get(Target, target_id)
        hostname = f"api.{target.value}"

        assets = persist_discovered_assets(
            db, scan_id, worker_id, [hostname, hostname.upper()]
        )

        assert len(assets) == 1

        db.commit()

        stored = (
            db.query(DiscoveredAsset)
            .filter_by(scan_id=scan_id)
            .all()
        )
        assert len(stored) == 1
    finally:
        generator.close()


def test_rejects_missing_scan(auth_client):
    generator, db = get_test_db(auth_client)

    try:
        with pytest.raises(
            DiscoveredAssetError,
            match="Scan not found",
        ):
            persist_discovered_assets(
                db, "missing-scan-id", "test-worker", ["api.example.com"]
            )
    finally:
        generator.close()
