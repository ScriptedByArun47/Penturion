from types import MappingProxyType
from typing import Mapping

from app.scanners.dependencies import validate_dependency_graph
from app.scanners.registry import AGENT_REGISTRY, AgentDefinition


class AgentScheduler:
    """
    Dependency-aware scheduler for PENTURION agents.

    This component manages agent states only.
    It does not execute scans or interact with the database.
    """

    def __init__(
        self,
        registry: Mapping[str, AgentDefinition] | None = None,
    ) -> None:
        self.registry = (
            registry if registry is not None else AGENT_REGISTRY
        )

        validate_dependency_graph(self.registry)

        self._states: dict[str, str] = {}
        self._skip_reasons: dict[str, str] = {}
        self._errors: dict[str, str] = {}

        for agent_id, agent in self.registry.items():
            if agent.enabled:
                self._states[agent_id] = "pending"
            else:
                self._states[agent_id] = "skipped"
                self._skip_reasons[agent_id] = "Agent is disabled."

    @property
    def states(self) -> Mapping[str, str]:
        """Return a read-only snapshot of agent states."""
        return MappingProxyType(self._states.copy())

    @property
    def skip_reasons(self) -> Mapping[str, str]:
        return MappingProxyType(self._skip_reasons.copy())

    @property
    def errors(self) -> Mapping[str, str]:
        return MappingProxyType(self._errors.copy())

    def _propagate_skips(self) -> None:
        """
        Skip pending agents whose dependencies failed or were skipped.
        Continue until all downstream skips have propagated.
        """

        changed = True

        while changed:
            changed = False

            for agent_id, agent in self.registry.items():
                if self._states[agent_id] != "pending":
                    continue

                for dependency in agent.dependencies:
                    dependency_state = self._states[dependency]

                    if dependency_state in {"failed", "skipped"}:
                        self._states[agent_id] = "skipped"

                        self._skip_reasons[agent_id] = (
                            f"Dependency {dependency} "
                            f"did not complete successfully."
                        )

                        changed = True
                        break

    def get_ready_agents(self) -> tuple[str, ...]:
        """
        Return pending agents whose dependencies are completed.
        """

        self._propagate_skips()

        ready = []

        for agent_id, agent in self.registry.items():
            if self._states[agent_id] != "pending":
                continue

            if all(
                self._states[dependency] == "completed"
                for dependency in agent.dependencies
            ):
                ready.append(agent_id)

        return tuple(ready)

    def mark_started(self, agent_id: str) -> None:
        """Move a ready agent from pending to running."""

        if agent_id not in self.registry:
            raise ValueError(f"Unknown agent: {agent_id}")

        if agent_id not in self.get_ready_agents():
            raise ValueError(
                f"Agent {agent_id} is not ready to start."
            )

        self._states[agent_id] = "running"

    def mark_completed(self, agent_id: str) -> None:
        """Move a running agent to completed."""

        self._require_running(agent_id)

        self._states[agent_id] = "completed"

    def mark_failed(self, agent_id: str, error: str) -> None:
        """Move a running agent to failed and propagate dependent skips."""

        self._require_running(agent_id)

        if not isinstance(error, str) or not error.strip():
            raise ValueError("Failure error must not be empty.")

        self._states[agent_id] = "failed"
        self._errors[agent_id] = error.strip()[:2000]

        # Immediately skip agents that depend on this failed agent.
        self._propagate_skips()

    def _require_running(self, agent_id: str) -> None:
        if agent_id not in self.registry:
            raise ValueError(f"Unknown agent: {agent_id}")

        if self._states[agent_id] != "running":
            raise ValueError(
                f"Agent {agent_id} is not running."
            )