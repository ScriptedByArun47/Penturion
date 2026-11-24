import pytest
from datetime import datetime, timedelta, timezone

from app.models.dns_record import DNSRecord
from app.models.target import Target
from app.models.scan import Scan
from app.scanners.agent_result import DNSRecordCandidate
from app.services.dns_record_service import (
    persist_dns_records,
    DNSRecordPersistenceError,
)
from app.services.discovered_asset_service import persist_discovered_assets

from tests.test_discovered_asset_service import prepare_running_scan


def prepare_dns_asset(auth_client, target_id):
    scan_id, worker_id, generator, db = prepare_running_scan(
        auth_client, target_id
    )

    target = db.get(Target, target_id)
    hostname = f"api.{target.value}"

    assets = persist_discovered_assets(
        db, scan_id, worker_id, [hostname]
    )

    return scan_id, worker_id, generator, db, assets[0]


def make_candidate(asset, **overrides):
    values = {
        "asset_id": asset.id,
        "record_name": asset.value,
        "record_type": "A",
        "value": "8.8.8.8",
        "ttl": 300,
        "priority": None,
    }
    values.update(overrides)
    return DNSRecordCandidate(**values)


def test_persists_valid_dns_record(auth_client, target_id):
    scan_id, worker_id, generator, db, asset = prepare_dns_asset(
        auth_client, target_id
    )

    try:
        candidate = make_candidate(asset)

        records = persist_dns_records(
            db, scan_id, worker_id, (candidate,)
        )

        assert len(records) == 1
        assert records[0].discovered_asset_id == asset.id
        assert records[0].record_name == asset.value
        assert records[0].record_type == "A"
        assert records[0].value == "8.8.8.8"
        assert records[0].ttl == 300

    finally:
        generator.close()


def test_duplicate_dns_records_are_idempotent(
    auth_client, target_id
):
    scan_id, worker_id, generator, db, asset = prepare_dns_asset(
        auth_client, target_id
    )

    try:
        candidate = make_candidate(asset)

        first = persist_dns_records(
            db, scan_id, worker_id, (candidate,)
        )

        second = persist_dns_records(
            db, scan_id, worker_id, (candidate,)
        )

        stored = (
            db.query(DNSRecord)
            .filter_by(discovered_asset_id=asset.id)
            .all()
        )

        assert len(first) == 1
        assert len(second) == 1
        assert len(stored) == 1

    finally:
        generator.close()


def test_rejects_out_of_scope_asset(auth_client, target_id):
    scan_id, worker_id, generator, db = prepare_running_scan(
        auth_client, target_id
    )

    try:
        target = db.get(Target, target_id)
        db.get(Scan, scan_id).authorization_request.requested_scope = (
            f'["api.{target.value}"]'
        )

        hostname = f"dev.{target.value}"

        assets = persist_discovered_assets(
            db, scan_id, worker_id, [hostname]
        )

        candidate = make_candidate(assets[0])

        with pytest.raises(
            DNSRecordPersistenceError,
            match="in-scope subdomains",
        ):
            persist_dns_records(
                db, scan_id, worker_id, (candidate,)
            )

    finally:
        generator.close()


def test_rejects_private_ip_address(auth_client, target_id):
    scan_id, worker_id, generator, db, asset = prepare_dns_asset(
        auth_client, target_id
    )

    try:
        candidate = make_candidate(
            asset,
            value="127.0.0.1",
        )

        with pytest.raises(
            DNSRecordPersistenceError,
            match="Invalid A record address",
        ):
            persist_dns_records(
                db, scan_id, worker_id, (candidate,)
            )

    finally:
        generator.close()


def test_rejects_expired_worker_lease(auth_client, target_id):
    scan_id, worker_id, generator, db, asset = prepare_dns_asset(
        auth_client, target_id
    )

    try:
        scan = db.get(Scan, scan_id)
        scan.lease_expires_at = (
            datetime.now(timezone.utc) - timedelta(minutes=1)
        )
        db.flush()

        with pytest.raises(
            DNSRecordPersistenceError,
            match="Worker lease is invalid",
        ):
            persist_dns_records(
                db,
                scan_id,
                worker_id,
                (make_candidate(asset),),
            )

    finally:
        generator.close()