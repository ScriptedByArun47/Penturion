from typing import Protocol
from threading import Event

from app.scanners.agent_context import AgentExecutionContext, AssetCandidate
from app.scanners.agent_result import AgentResult
from app.scanners.executor import AgentExecutionCancelled
from app.scanners.scope import (
    ScopeValidationError,
    host_matches_domain,
    normalize_hostname,
    validate_target_in_scope,
)


class SubdomainDiscoveryProvider(Protocol):
    def discover(
        self,
        *,
        root_domain: str,
        timeout_seconds: int,
        cancel_event: Event,
    ) -> list[str]:
        """Return passively discovered hostnames."""
        ...


class SubdomainDiscoveryAgent:
    agent_id = "A01"

    def __init__(self, provider: SubdomainDiscoveryProvider):
        self.provider = provider

    def execute(self, context: AgentExecutionContext) -> AgentResult:
        if context.target_type != "domain":
            return AgentResult(
                agent_id=self.agent_id,
                success=False,
                error="A01 requires an authorized domain target.",
            )

        try:
            validate_target_in_scope(
                f"https://{context.target}",
                context.authorized_value,
                context.target_type,
            )
            root_domain = normalize_hostname(context.authorized_value)

            if context.cancel_event.is_set():
                raise AgentExecutionCancelled(
                    "Subdomain discovery was cancelled."
                )

            discovered = self.provider.discover(
                root_domain=root_domain,
                timeout_seconds=context.timeout_seconds,
                cancel_event=context.cancel_event,
            )

            if context.cancel_event.is_set():
                raise AgentExecutionCancelled(
                    "Subdomain discovery was cancelled."
                )

            candidates = set()

            for hostname in discovered:
                if not isinstance(hostname, str):
                    continue

                try:
                    normalized = normalize_hostname(hostname)
                except (ScopeValidationError, ValueError):
                    continue

                if normalized == root_domain:
                    continue

                if not host_matches_domain(normalized, root_domain):
                    continue

                candidates.add(normalized)

            return AgentResult(
                agent_id=self.agent_id,
                success=True,
                asset_candidates=tuple(
                    AssetCandidate(value, "subdomain")
                    for value in sorted(candidates)
                ),
            )

        except AgentExecutionCancelled:
            raise

        except Exception as exc:
            return AgentResult(
                agent_id=self.agent_id,
                success=False,
                error=f"Subdomain discovery failed: {exc}",
            )
