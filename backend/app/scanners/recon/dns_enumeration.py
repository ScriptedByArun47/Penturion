"""A02 DNS enumeration agent."""

import time
from typing import Protocol

from threading import Event

from app.scanners.agent_context import AgentExecutionContext
from app.scanners.agent_result import AgentResult, DNSRecordCandidate
from app.scanners.executor import AgentExecutionCancelled
from app.scanners.recon.dns_provider import (
    DNSRecordData,
    DNSRecordProvider,
)
from app.scanners.scope import (
    ScopeValidationError,
    host_matches_domain,
    normalize_hostname,
)


class DNSProvider(Protocol):
    def collect(
        self,
        *,
        hostname: str,
        timeout_seconds: int,
        cancel_event: Event,
    ) -> list[DNSRecordData]:
        ...


class DNSEnumerationAgent:
    agent_id = "A02"

    def __init__(self, provider: DNSProvider | None = None):
        self.provider = provider or DNSRecordProvider()

    def execute(self, context: AgentExecutionContext) -> AgentResult:
        if context.target_type != "domain":
            return AgentResult(
                agent_id=self.agent_id,
                success=False,
                error="A02 requires an authorized domain target.",
            )

        try:
            root_domain = normalize_hostname(context.authorized_value)
            target = normalize_hostname(context.target)

            if target != root_domain:
                return AgentResult(
                    agent_id=self.agent_id,
                    success=False,
                    error="A02 target does not match the authorized root domain.",
                )

            deadline = time.monotonic() + context.timeout_seconds
            results = []

            for asset in context.discovered_assets:
                if context.cancel_event.is_set():
                    raise AgentExecutionCancelled(
                        "DNS enumeration was cancelled."
                    )

                # Only persisted subdomain assets with database IDs
                # can be processed.
                if ( asset.asset_type != "subdomain"  or not asset.asset_id or asset.scope_status != "in_scope" ):
                    continue

                try:
                    hostname = normalize_hostname(asset.value)
                except (ScopeValidationError, ValueError):
                    continue

                # Never query a hostname outside the authorized root.
                if not host_matches_domain(hostname, root_domain):
                    continue

                remaining = int(deadline - time.monotonic())

                if remaining <= 0:
                    return AgentResult(
                        agent_id=self.agent_id,
                        success=False,
                        error="DNS enumeration exceeded its timeout.",
                    )

                records = self.provider.collect(
                    hostname=hostname,
                    timeout_seconds=remaining,
                    cancel_event=context.cancel_event,
                )

                if context.cancel_event.is_set():
                    raise AgentExecutionCancelled(
                        "DNS enumeration was cancelled."
                    )

                for record in records:
                    results.append(
                        DNSRecordCandidate(
                            asset_id=asset.asset_id,
                            record_name=record.record_name,
                            record_type=record.record_type,
                            value=record.value,
                            ttl=record.ttl,
                            priority=record.priority,
                        )
                    )

            return AgentResult(
                agent_id=self.agent_id,
                success=True,
                dns_records=tuple(results),
            )

        except AgentExecutionCancelled:
            raise

        except Exception as exc:
            return AgentResult(
                agent_id=self.agent_id,
                success=False,
                error=f"DNS enumeration failed: {exc}",
            )