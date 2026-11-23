
"""Persistence and authorization checks for discovered assets."""

import json
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.scan import Scan
from app.models.discovered_asset import DiscoveredAsset
from app.services.authorization_scope import (
    AuthorizationScopeError,
    validate_authorization_scope,
)
from app.scanners.scope import (
    host_matches_domain,
    normalize_hostname,
)


class DiscoveredAssetError(Exception):
    """Raised when discovered assets cannot be safely processed."""


def persist_discovered_assets(
    db: Session,
    scan_id: str,
    worker_id: str,
    hostnames: list[str],
) -> list[DiscoveredAsset]:
    """Persist discovered hostnames after validating worker and scope."""

    if not isinstance(worker_id, str) or not worker_id.strip():
        raise DiscoveredAssetError("Invalid worker ID")

    if len(worker_id) > 100:
        raise DiscoveredAssetError("Invalid worker ID")

    now = datetime.now(timezone.utc)

    scan = db.get(Scan, scan_id)

    if scan is None:
        raise DiscoveredAssetError("Scan not found")

    # SQLite may return naive datetimes even with timezone=True.
    lease_expires_at = scan.lease_expires_at

    if lease_expires_at is not None and lease_expires_at.tzinfo is None:
        lease_expires_at = lease_expires_at.replace(tzinfo=timezone.utc)

    # Verify current worker ownership, lease and cancellation state.
    if (
        scan.status != "running"
        or scan.worker_id != worker_id
        or lease_expires_at is None
        or lease_expires_at <= now
        or scan.cancel_requested_at is not None
    ):
        raise DiscoveredAssetError(
            "Worker lease is invalid or cancellation was requested"
        )

    target = scan.target
    authorization = scan.authorization_request

    if authorization is None:
        raise DiscoveredAssetError("Authorization request not found")

    if authorization.status != "approved":
        raise DiscoveredAssetError("Authorization is not approved")

    if authorization.target_id != target.id:
        raise DiscoveredAssetError(
            "Authorization does not belong to the scan target"
        )

    if target.authorization_status != "approved":
        raise DiscoveredAssetError("Target is no longer approved")

    # Revalidate authorization expiry.
    if authorization.expires_at is not None:
        expires_at = authorization.expires_at

        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if expires_at <= now:
            raise DiscoveredAssetError("Authorization has expired")

    if target.target_type != "domain":
        raise DiscoveredAssetError(
            "Subdomain discovery requires a domain target"
        )

    # Validate the approved entries against the registered root.
    try:
        canonical_scope = validate_authorization_scope(
            authorization.requested_scope,
            target.value,
            target.target_type,
        )

        approved_entries = json.loads(canonical_scope)
        root_domain = normalize_hostname(target.value)

    except (AuthorizationScopeError, ValueError) as exc:
        raise DiscoveredAssetError(
            "Authorization scope validation failed"
        ) from exc

    results = []
    processed = set()

    for hostname in hostnames:
        if not isinstance(hostname, str):
            continue

        try:
            normalized = normalize_hostname(hostname)
        except ValueError:
            continue

        # Reject anything outside the registered root domain.
        if not host_matches_domain(normalized, root_domain):
            continue

        if normalized in processed:
            continue

        processed.add(normalized)

        # Exact approved scope determines active-testing eligibility.
        in_scope = any(
            host_matches_domain(normalized, entry)
            for entry in approved_entries
        )

        asset = db.scalar(
            select(DiscoveredAsset).where(
                DiscoveredAsset.scan_id == scan_id,
                DiscoveredAsset.value == normalized,
            )
        )

        if asset is None:
            asset = DiscoveredAsset(
                scan_id=scan_id,
                value=normalized,
                asset_type="subdomain",
                source_agent="A01",
                scope_status="in_scope" if in_scope else "out_of_scope",
            )
            db.add(asset)
        else:
            asset.scope_status = (
                "in_scope" if in_scope else "out_of_scope"
            )

        results.append(asset)

    db.flush()

    return results
