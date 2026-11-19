
"""Concurrent execution engine for PENTURION security agents."""

from concurrent.futures import (
    Future,
    ThreadPoolExecutor,
    as_completed,
)
from threading import Event
from typing import Mapping, Protocol

from app.scanners.agent_context import AgentExecutionContext
from app.scanners.agent_result import AgentResult
from app.scanners.registry import (
    AGENT_REGISTRY,
    AgentDefinition,
)


class SecurityAgent(Protocol):
    """Interface that every PENTURION agent must implement."""

    def execute(
        self,
        context: AgentExecutionContext,
    ) -> AgentResult:
        ...


class AgentExecutionCancelled(Exception):
    """Raised when an agent execution is cancelled."""


class AgentExecutor:
    """Execute independent security agents concurrently."""

    MAX_WORKERS = 5

    def __init__(
        self,
        implementations: Mapping[str, SecurityAgent],
        registry: Mapping[str, AgentDefinition] | None = None,
        max_workers: int = 5,
    ) -> None:
        if not 1 <= max_workers <= self.MAX_WORKERS:
            raise ValueError(
                f"max_workers must be between 1 and {self.MAX_WORKERS}"
            )

        self.registry = (
            registry if registry is not None else AGENT_REGISTRY
        )

        for agent_id, implementation in implementations.items():
            if agent_id not in self.registry:
                raise ValueError(
                    f"Unknown agent implementation: {agent_id}"
                )

            if not self.registry[agent_id].enabled:
                raise ValueError(
                    f"Agent {agent_id} is disabled."
                )

            if not callable(getattr(implementation, "execute", None)):
                raise TypeError(
                    f"Agent {agent_id} must implement execute()."
                )

        self.implementations = dict(implementations)
        self.max_workers = max_workers

    def _execute_one(
        self,
        agent_id: str,
        context: AgentExecutionContext,
    ) -> AgentResult:
        """Execute one agent and normalize unexpected errors."""

        if context.cancel_event.is_set():
            raise AgentExecutionCancelled(
                f"Execution of {agent_id} cancelled before starting."
            )

        implementation = self.implementations[agent_id]

        try:
            result = implementation.execute(context)

            if not isinstance(result, AgentResult):
                raise TypeError(
                    "Agent must return an AgentResult."
                )

            if result.agent_id != agent_id:
                raise ValueError(
                    f"Expected result from {agent_id}, "
                    f"received {result.agent_id}."
                )

            return result

        except AgentExecutionCancelled:
            raise

        except Exception as exc:
            return AgentResult(
                agent_id=agent_id,
                success=False,
                error=f"{type(exc).__name__}: {exc}"[:2000],
            )

    def execute_batch(
        self,
        agent_ids: tuple[str, ...],
        context: AgentExecutionContext,
    ) -> dict[str, AgentResult]:
        """
        Execute a batch of independent agents.

        Returns successful and failed results.
        Cancelled executions raise AgentExecutionCancelled.
        """

        if not agent_ids:
            return {}

        if len(agent_ids) != len(set(agent_ids)):
            raise ValueError("Duplicate agent IDs in execution batch.")

        for agent_id in agent_ids:
            if agent_id not in self.implementations:
                raise ValueError(
                    f"No implementation registered for {agent_id}."
                )

        results: dict[str, AgentResult] = {}
        futures: dict[Future[AgentResult], str] = {}

        executor = ThreadPoolExecutor(
            max_workers=self.max_workers,
            thread_name_prefix="penturion-agent",
        )

        try:
            for agent_id in agent_ids:
                if context.cancel_event.is_set():
                    raise AgentExecutionCancelled(
                        "Scan cancelled before all agents were submitted."
                    )

                future = executor.submit(
                    self._execute_one,
                    agent_id,
                    context,
                )

                futures[future] = agent_id

            for future in as_completed(futures):
                if context.cancel_event.is_set():
                    raise AgentExecutionCancelled(
                        "Scan cancellation requested."
                    )

                agent_id = futures[future]

                try:
                    results[agent_id] = future.result()

                except AgentExecutionCancelled:
                    raise

                except Exception as exc:
                    results[agent_id] = AgentResult(
                        agent_id=agent_id,
                        success=False,
                        error=f"{type(exc).__name__}: {exc}"[:2000],
                    )

            return results

        except BaseException:
            context.cancel_event.set()

            for future in futures:
                future.cancel()

            raise

        finally:
            executor.shutdown(
                wait=True,
                cancel_futures=True,
            )
