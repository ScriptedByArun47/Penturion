"""Persistence and authorization checks for DNS records."""

import ipaddress
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.scan import Scan
from app.models.discovered_asset import DiscoveredAsset
from app.models.dns_record import DNSRecord
from app.scanners.agent_result import DNSRecordCandidate
from app.scanners.scope import (
    ScopeValidationError,
    host_matches_domain,
    normalize_hostname,
    validate_destination_ip,
)
from app.services.authorization_scope import (
    AuthorizationScopeError,
    validate_authorization_scope,
)


SUPPORTED_DNS_RECORD_TYPES = {
    "A",
    "AAAA",
    "CNAME",
    "MX",
    "NS",
    "TXT",
    "SOA",
}


class DNSRecordPersistenceError(Exception):
    """Raised when DNS records cannot be safely persisted."""


def validate_dns_scan_access(
    db: Session,
    scan_id: str,
    worker_id: str,
) -> str:
    """Validate worker ownership and authorization before DNS processing."""

    if not isinstance(worker_id, str) or not worker_id.strip():
        raise DNSRecordPersistenceError("Invalid worker ID")

    if len(worker_id) > 100:
        raise DNSRecordPersistenceError("Invalid worker ID")

    now = datetime.now(timezone.utc)
    scan = db.get(Scan, scan_id)

    if scan is None:
        raise DNSRecordPersistenceError("Scan not found")

    lease_expires_at = scan.lease_expires_at

    if (
        lease_expires_at is not None
        and lease_expires_at.tzinfo is None
    ):
        lease_expires_at = lease_expires_at.replace(
            tzinfo=timezone.utc
        )

    if (
        scan.status != "running"
        or scan.worker_id != worker_id
        or lease_expires_at is None
        or lease_expires_at <= now
        or scan.cancel_requested_at is not None
    ):
        raise DNSRecordPersistenceError(
            "Worker lease is invalid or cancellation was requested"
        )

    target = scan.target
    authorization = scan.authorization_request

    if authorization is None:
        raise DNSRecordPersistenceError(
            "Authorization request not found"
        )

    if authorization.status != "approved":
        raise DNSRecordPersistenceError(
            "Authorization is not approved"
        )

    if authorization.target_id != target.id:
        raise DNSRecordPersistenceError(
            "Authorization does not belong to the scan target"
        )

    if target.authorization_status != "approved":
        raise DNSRecordPersistenceError(
            "Target is no longer approved"
        )

    if authorization.expires_at is not None:
        expires_at = authorization.expires_at

        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(
                tzinfo=timezone.utc
            )

        if expires_at <= now:
            raise DNSRecordPersistenceError(
                "Authorization has expired"
            )

    if target.target_type != "domain":
        raise DNSRecordPersistenceError(
            "DNS enumeration requires a domain target"
        )

    try:
        validate_authorization_scope(
            authorization.requested_scope,
            target.value,
            target.target_type,
        )

        root_domain = normalize_hostname(target.value)

    except (AuthorizationScopeError, ScopeValidationError, ValueError) as exc:
        raise DNSRecordPersistenceError(
            "Authorization scope validation failed"
        ) from exc

    return root_domain


def persist_dns_records(
    db: Session,
    scan_id: str,
    worker_id: str,
    dns_records: tuple[DNSRecordCandidate, ...],
) -> list[DNSRecord]:
    """Persist validated DNS records without committing the transaction."""

    root_domain = validate_dns_scan_access(
        db=db,
        scan_id=scan_id,
        worker_id=worker_id,
    )

    persisted_records = []

    for candidate in dns_records:
        if not isinstance(candidate.asset_id, str) or not candidate.asset_id:
            raise DNSRecordPersistenceError(
                "DNS record must reference a persisted asset"
            )

        record_type = candidate.record_type

        if not isinstance(record_type, str):
            raise DNSRecordPersistenceError(
                "Invalid DNS record type"
            )

        record_type = record_type.upper()

        if record_type not in SUPPORTED_DNS_RECORD_TYPES:
            raise DNSRecordPersistenceError(
                f"Unsupported DNS record type: {record_type}"
            )

        asset = db.scalar(
            select(DiscoveredAsset).where(
                DiscoveredAsset.id == candidate.asset_id,
                DiscoveredAsset.scan_id == scan_id,
            )
        )

        if asset is None:
            raise DNSRecordPersistenceError(
                "DNS record references an asset outside this scan"
            )

        if (
            asset.asset_type != "subdomain"
            or asset.scope_status != "in_scope"
        ):
            raise DNSRecordPersistenceError(
                "DNS records can only be stored for in-scope subdomains"
            )

        try:
            asset_hostname = normalize_hostname(asset.value)
            record_name = normalize_hostname(candidate.record_name)

        except (ScopeValidationError, ValueError, AttributeError) as exc:
            raise DNSRecordPersistenceError(
                "Invalid DNS record hostname"
            ) from exc

        if (
            not host_matches_domain(asset_hostname, root_domain)
            or record_name != asset_hostname
        ):
            raise DNSRecordPersistenceError(
                "DNS record name does not match its authorized asset"
            )

        if not isinstance(candidate.value, str) or not candidate.value:
            raise DNSRecordPersistenceError(
                "DNS record value cannot be empty"
            )

        if len(candidate.value) > 4096:
            raise DNSRecordPersistenceError(
                "DNS record value is too long"
            )

        for field_name in ("ttl", "priority"):
            field_value = getattr(candidate, field_name)

            if (
                field_value is not None
                and (
                    isinstance(field_value, bool)
                    or not isinstance(field_value, int)
                    or field_value < 0
                )
            ):
                raise DNSRecordPersistenceError(
                    f"Invalid DNS record {field_name}"
                )

        value = candidate.value

        if record_type in {"A", "AAAA"}:
            try:
                ip = validate_destination_ip(value)

                if record_type == "A" and not isinstance(
                    ip, ipaddress.IPv4Address
                ):
                    raise DNSRecordPersistenceError(
                        "A records must contain IPv4 addresses"
                    )

                if record_type == "AAAA" and not isinstance(
                    ip, ipaddress.IPv6Address
                ):
                    raise DNSRecordPersistenceError(
                        "AAAA records must contain IPv6 addresses"
                    )

                value = str(ip)

            except ScopeValidationError as exc:
                raise DNSRecordPersistenceError(
                    f"Invalid {record_type} record address"
                ) from exc

        existing = db.scalar(
            select(DNSRecord).where(
                DNSRecord.discovered_asset_id == asset.id,
                DNSRecord.record_type == record_type,
                DNSRecord.value == value,
            )
        )

        if existing is not None:
            existing.record_name = record_name
            existing.ttl = candidate.ttl
            existing.priority = candidate.priority
            persisted_records.append(existing)
            continue

        record = DNSRecord(
            discovered_asset_id=asset.id,
            record_name=record_name,
            record_type=record_type,
            value=value,
            ttl=candidate.ttl,
            priority=candidate.priority,
        )

        db.add(record)
        persisted_records.append(record)

    db.flush()

    return persisted_records