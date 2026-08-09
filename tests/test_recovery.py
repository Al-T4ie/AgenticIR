"""Crash recovery: what happens to a run whose process went away.

Investigations are driven by an in-process asyncio task. The checkpointer keeps
the graph state, but nothing resumes a thread whose driver vanished — so on a
deploy, an OOM kill or a Hetzner reboot, every in-flight incident would sit at
`running` forever. Worse than stalled: `follow_up_investigation` refuses to
re-enter a running incident, so it would queue telemetry against it
indefinitely and never apply any of it.

`recover_interrupted()` is the thing that prevents that, it runs exactly once
per boot, and until now it had no test — which made it the least verified code
on the most consequential path.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.services import runner


class _Snapshot:
    def __init__(self, next_nodes: tuple[str, ...], values: dict[str, Any]) -> None:
        self.next = next_nodes
        self.values = values


class _Graph:
    def __init__(self, snapshots: dict[str, _Snapshot]) -> None:
        self.snapshots = snapshots
        self.asked: list[str] = []

    async def aget_state(self, config: dict[str, Any]) -> _Snapshot:
        thread_id = config["configurable"]["thread_id"]
        self.asked.append(thread_id)
        if thread_id not in self.snapshots:
            raise RuntimeError(f"no checkpoint for {thread_id}")
        return self.snapshots[thread_id]


@pytest.fixture
def recovery(monkeypatch: pytest.MonkeyPatch):
    """Wire up the collaborators recovery touches, recording what it does."""
    state: dict[str, Any] = {
        "lock": True,
        "rows": [],
        "graph": _Graph({}),
        "saved": [],
        "spawned": [],
    }

    class _Result:
        def __init__(self, value: Any) -> None:
            self._value = value

        def scalar(self) -> Any:
            return self._value

    class _Session:
        async def execute(self, *_a: Any, **_k: Any) -> _Result:
            return _Result(state["lock"])

    class _Scope:
        async def __aenter__(self) -> _Session:
            return _Session()

        async def __aexit__(self, *_a: Any) -> None:
            return None

    monkeypatch.setattr("app.db.session.session_scope", lambda: _Scope())
    monkeypatch.setattr(runner, "get_graph", lambda: state["graph"])

    async def _list(**kwargs: Any) -> list[dict[str, Any]]:
        assert kwargs.get("status") == "running", "recovery must only look at running incidents"
        return state["rows"]

    async def _save(incident_id: str, values: dict[str, Any], status: str = "") -> None:
        state["saved"].append((incident_id, status, values))

    monkeypatch.setattr(runner.incidents, "list_incidents", _list)
    monkeypatch.setattr(runner.incidents, "save_state", _save)

    def _spawn(coro: Any):
        coro.close()  # never actually drive the graph in a unit test
        state["spawned"].append(True)
        return None

    monkeypatch.setattr(runner, "_spawn", _spawn)
    return state


async def test_nothing_running_is_not_an_error(recovery: dict[str, Any]) -> None:
    assert await runner.recover_interrupted() == 0
    assert recovery["spawned"] == []


async def test_a_run_left_mid_flight_is_resumed(recovery: dict[str, Any]) -> None:
    recovery["rows"] = [{"id": "INC-1", "thread_id": "t-1"}]
    recovery["graph"] = _Graph({"t-1": _Snapshot(("critic",), {"verdict": "unknown"})})

    assert await runner.recover_interrupted() == 1
    assert recovery["spawned"] == [True]


async def test_a_finished_run_is_corrected_not_re_executed(recovery: dict[str, Any]) -> None:
    """Empty `next` means the graph finished and only the projection is stale.

    Re-invoking would re-run the report node and post a second report into the
    thread for an investigation that already concluded.
    """
    recovery["rows"] = [{"id": "INC-2", "thread_id": "t-2"}]
    recovery["graph"] = _Graph({"t-2": _Snapshot((), {"verdict": "true_positive"})})

    assert await runner.recover_interrupted() == 0
    assert recovery["spawned"] == []
    assert recovery["saved"] == [("INC-2", "completed", {"verdict": "true_positive"})]


async def test_only_one_worker_recovers(recovery: dict[str, Any]) -> None:
    """The advisory lock is what stops N workers resuming the same thread N times."""
    recovery["lock"] = False
    recovery["rows"] = [{"id": "INC-3", "thread_id": "t-3"}]
    recovery["graph"] = _Graph({"t-3": _Snapshot(("critic",), {})})

    assert await runner.recover_interrupted() == 0
    assert recovery["spawned"] == []
    # It must not even look: reading state for threads another worker is
    # already resuming is wasted round trips at the worst possible moment.
    assert recovery["graph"].asked == []


async def test_one_unreadable_checkpoint_does_not_strand_the_others(
    recovery: dict[str, Any],
) -> None:
    """Boot-time recovery is all-or-nothing per incident, never per batch."""
    recovery["rows"] = [
        {"id": "INC-4", "thread_id": "t-missing"},
        {"id": "INC-5", "thread_id": "t-5"},
    ]
    recovery["graph"] = _Graph({"t-5": _Snapshot(("supervisor",), {})})

    assert await runner.recover_interrupted() == 1
    assert recovery["spawned"] == [True]


async def test_recovery_is_bounded(recovery: dict[str, Any]) -> None:
    """A caller can cap the batch; the cap is passed to the query, not applied after."""
    seen: dict[str, Any] = {}

    async def _list(**kwargs: Any) -> list[dict[str, Any]]:
        seen.update(kwargs)
        return []

    recovery["rows"] = []
    import app.services.incidents as incidents_module

    original = incidents_module.list_incidents
    incidents_module.list_incidents = _list  # type: ignore[assignment]
    try:
        await runner.recover_interrupted(limit=5)
    finally:
        incidents_module.list_incidents = original  # type: ignore[assignment]

    assert seen.get("limit") == 5
