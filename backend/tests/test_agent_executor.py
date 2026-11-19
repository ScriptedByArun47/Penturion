import threading
from dataclasses import replace

import pytest

from app.scanners.agent_context import AgentExecutionContext
from app.scanners.agent_result import AgentResult
from app.scanners.executor import (
    AgentExecutionCancelled,
    AgentExecutor,
)
from app.scanners.registry import AGENT_REGISTRY


class FakeLimiter:
    def acquire(self, host, timeout=None):
        return True

    def release(self, host):
        pass


class SuccessfulAgent:
    def __init__(self, agent_id):
        self.agent_id = agent_id

    def execute(self, context):
        return AgentResult(
            agent_id=self.agent_id,
            success=True,
        )


class FailingAgent:
    def execute(self, context):
        raise RuntimeError("Simulated agent failure")


class IncorrectAgent:
    def execute(self, context):
        return AgentResult(
            agent_id="A99",
            success=True,
        )


def make_registry(*agent_ids):
    return {
        agent_id: replace(
            AGENT_REGISTRY[agent_id],
            enabled=True,
            dependencies=(),
        )
        for agent_id in agent_ids
    }


def make_context(cancel_event=None):
    return AgentExecutionContext(
        scan_id="test-scan",
        target="example.com",
        target_type="domain",
        authorized_value="example.com",
        timeout_seconds=30,
        cancel_event=cancel_event or threading.Event(),
        request_limiter=FakeLimiter(),
    )


def test_successful_agent_execution():
    registry = make_registry("A01")

    executor = AgentExecutor(
        implementations={"A01": SuccessfulAgent("A01")},
        registry=registry,
    )

    results = executor.execute_batch(
        ("A01",),
        make_context(),
    )

    assert results["A01"].success is True


def test_multiple_agents_execute_concurrently():
    registry = make_registry("A01", "A02")
    barrier = threading.Barrier(2)

    class ConcurrentAgent:
        def __init__(self, agent_id):
            self.agent_id = agent_id

        def execute(self, context):
            barrier.wait(timeout=3)

            return AgentResult(
                agent_id=self.agent_id,
                success=True,
            )

    executor = AgentExecutor(
        implementations={
            "A01": ConcurrentAgent("A01"),
            "A02": ConcurrentAgent("A02"),
        },
        registry=registry,
        max_workers=2,
    )

    results = executor.execute_batch(
        ("A01", "A02"),
        make_context(),
    )

    assert len(results) == 2
    assert all(result.success for result in results.values())


def test_agent_exception_becomes_failed_result():
    registry = make_registry("A01")

    executor = AgentExecutor(
        implementations={"A01": FailingAgent()},
        registry=registry,
    )

    results = executor.execute_batch(
        ("A01",),
        make_context(),
    )

    assert results["A01"].success is False
    assert "Simulated agent failure" in results["A01"].error


def test_incorrect_agent_result_becomes_failure():
    registry = make_registry("A01")

    executor = AgentExecutor(
        implementations={"A01": IncorrectAgent()},
        registry=registry,
    )

    results = executor.execute_batch(
        ("A01",),
        make_context(),
    )

    assert results["A01"].success is False
    assert "Expected result from A01" in results["A01"].error


def test_unknown_agent_is_rejected():
    with pytest.raises(ValueError):
        AgentExecutor(
            implementations={"A99": SuccessfulAgent("A99")},
        )


def test_disabled_agent_is_rejected():
    with pytest.raises(ValueError):
        AgentExecutor(
            implementations={"A01": SuccessfulAgent("A01")},
        )


def test_duplicate_agent_ids_are_rejected():
    registry = make_registry("A01")

    executor = AgentExecutor(
        implementations={"A01": SuccessfulAgent("A01")},
        registry=registry,
    )

    with pytest.raises(ValueError):
        executor.execute_batch(
            ("A01", "A01"),
            make_context(),
        )


def test_missing_implementation_is_rejected():
    registry = make_registry("A01")

    executor = AgentExecutor(
        implementations={},
        registry=registry,
    )

    with pytest.raises(ValueError):
        executor.execute_batch(
            ("A01",),
            make_context(),
        )


def test_cancellation_before_execution():
    registry = make_registry("A01")
    cancel_event = threading.Event()
    cancel_event.set()

    executor = AgentExecutor(
        implementations={"A01": SuccessfulAgent("A01")},
        registry=registry,
    )

    with pytest.raises(AgentExecutionCancelled):
        executor.execute_batch(
            ("A01",),
            make_context(cancel_event),
        )


def test_invalid_worker_count():
    with pytest.raises(ValueError):
        AgentExecutor(
            implementations={},
            max_workers=0,
        )

    with pytest.raises(ValueError):
        AgentExecutor(
            implementations={},
            max_workers=6,
        )