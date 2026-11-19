from collections import deque
from typing import Mapping

from app.scanners.registry import (
    AGENT_REGISTRY,
    AgentDefinition,
)


def validate_dependency_graph(
    registry: Mapping[str, AgentDefinition] | None = None,
) -> None:
    """
    Validate agent dependencies.

    Checks:
    - Registry keys match agent IDs.
    - No duplicate dependencies.
    - No self-dependencies.
    - Every dependency references a registered agent.
    - No circular dependencies exist.
    """

    agents = registry or AGENT_REGISTRY

    # Validate registry identity and dependency references.
    for agent_id, agent in agents.items():

        if agent_id != agent.agent_id:
            raise ValueError(
                f"Registry key '{agent_id}' does not match "
                f"agent ID '{agent.agent_id}'."
            )

        if len(agent.dependencies) != len(set(agent.dependencies)):
            raise ValueError(
                f"Agent {agent_id} contains duplicate dependencies."
            )

        if agent_id in agent.dependencies:
            raise ValueError(
                f"Agent {agent_id} cannot depend on itself."
            )

        for dependency in agent.dependencies:
            if dependency not in agents:
                raise ValueError(
                    f"Agent {agent_id} depends on unknown agent "
                    f"'{dependency}'."
                )

    # Kahn's algorithm for cycle detection.
    in_degree = {
        agent_id: len(agent.dependencies)
        for agent_id, agent in agents.items()
    }

    dependents = {
        agent_id: []
        for agent_id in agents
    }

    for agent_id, agent in agents.items():
        for dependency in agent.dependencies:
            dependents[dependency].append(agent_id)

    queue = deque(
        agent_id
        for agent_id in agents
        if in_degree[agent_id] == 0
    )

    processed = 0

    while queue:
        current = queue.popleft()
        processed += 1

        for dependent in dependents[current]:
            in_degree[dependent] -= 1

            if in_degree[dependent] == 0:
                queue.append(dependent)

    if processed != len(agents):
        remaining = [
            agent_id
            for agent_id, degree in in_degree.items()
            if degree > 0
        ]

        raise ValueError(
            "Circular dependency detected involving: "
            + ", ".join(remaining)
        )


def get_execution_order(
    registry: Mapping[str, AgentDefinition] | None = None,
) -> tuple[str, ...]:
    """
    Return a valid topological execution order.

    Dependencies always appear before their dependent agents.
    """

    agents = registry or AGENT_REGISTRY

    validate_dependency_graph(agents)

    in_degree = {
        agent_id: len(agent.dependencies)
        for agent_id, agent in agents.items()
    }

    dependents = {
        agent_id: []
        for agent_id in agents
    }

    for agent_id, agent in agents.items():
        for dependency in agent.dependencies:
            dependents[dependency].append(agent_id)

    queue = deque(
        agent_id
        for agent_id in agents
        if in_degree[agent_id] == 0
    )

    execution_order = []

    while queue:
        current = queue.popleft()
        execution_order.append(current)

        for dependent in dependents[current]:
            in_degree[dependent] -= 1

            if in_degree[dependent] == 0:
                queue.append(dependent)

    return tuple(execution_order)