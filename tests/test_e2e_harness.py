"""The release gate needs to be trustworthy before its verdict means anything.

Two deploys in this project's history were reported as verified when they had
not swapped, both times because a check matched a metric *name* rather than a
metric *sample* — `# HELP agenticir_slack_poll_cycles_total …` contains the name
and satisfies a naive grep. So the harness's own parsing is tested here, along
with the grading rule that decides the exit code.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

_PATH = Path(__file__).resolve().parent.parent / "infra" / "scripts" / "e2e_scenario.py"


def _load() -> Any:
    spec = importlib.util.spec_from_file_location("e2e_scenario", _PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    # @dataclass resolves annotations through sys.modules[cls.__module__], so a
    # module executed without being registered there blows up on its first
    # dataclass rather than on anything to do with the test.
    sys.modules["e2e_scenario"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def e2e() -> Any:
    return _load()


EXPOSITION = """\
# HELP agenticir_slack_poll_cycles_total Poll sweeps
# TYPE agenticir_slack_poll_cycles_total counter
agenticir_slack_poll_cycles_total{outcome="ok"} 396.0
agenticir_slack_poll_cycles_total{outcome="error"} 2.0
# HELP process_start_time_seconds Start time of the process since unix epoch.
# TYPE process_start_time_seconds gauge
process_start_time_seconds 1.78627119149e+09
"""


def test_series_sums_labelled_samples(e2e: Any) -> None:
    assert e2e.series(EXPOSITION, "agenticir_slack_poll_cycles_total") == 398.0


def test_series_reads_unlabelled_gauges(e2e: Any) -> None:
    assert e2e.series(EXPOSITION, "process_start_time_seconds") == pytest.approx(1786271191.49)


def test_series_ignores_help_and_type_comments(e2e: Any) -> None:
    """A metric declared but never incremented must read as zero, not as present."""
    declared_only = (
        "# HELP agenticir_runs_started_total Investigations started\n"
        "# TYPE agenticir_runs_started_total counter\n"
    )
    assert e2e.series(declared_only, "agenticir_runs_started_total") == 0.0


def test_series_does_not_match_a_longer_metric_name(e2e: Any) -> None:
    """`foo_total` must not pick up samples of `foo_total_bytes`."""
    text = 'agenticir_runs_started_total_bytes{source="ui"} 7.0\n'
    assert e2e.series(text, "agenticir_runs_started_total") == 0.0


def test_missing_metric_is_zero_not_an_error(e2e: Any) -> None:
    assert e2e.series(EXPOSITION, "agenticir_nonexistent_total") == 0.0


# ── Grading ──────────────────────────────────────────────────────────────────
def test_only_blockers_fail_the_run(e2e: Any, capsys: pytest.CaptureFixture[str]) -> None:
    """A warning says "could not prove it", which is not the same as "broken"."""
    rep = e2e.Report()
    rep.check("p", "a real failure", False, grade=e2e.BLOCKER)
    rep.check("p", "unverified", False, grade=e2e.WARN)
    rep.check("p", "fine", True)

    assert [c.name for c in rep.blockers()] == ["a real failure"]
    assert [c.name for c in rep.warnings()] == ["unverified"]
    assert e2e.summarise(rep, "INC-1", "https://example.test") == 1


def test_warnings_alone_still_pass(e2e: Any, capsys: pytest.CaptureFixture[str]) -> None:
    rep = e2e.Report()
    rep.check("p", "unverified", False, grade=e2e.WARN)
    rep.note("p", "context", "a fact, not a check")
    assert e2e.summarise(rep, "INC-1", "https://example.test") == 0


def test_notes_are_not_counted_as_checks(e2e: Any, capsys: pytest.CaptureFixture[str]) -> None:
    rep = e2e.Report()
    rep.note("p", "uptime", "14 min")
    e2e.summarise(rep, "", "https://example.test")
    assert "0/0 checks passed" in capsys.readouterr().out


# ── Text helpers ─────────────────────────────────────────────────────────────
def test_strip_tags_leaves_readable_text(e2e: Any) -> None:
    html = "<p>Verdict: <b>true positive</b></p>"
    assert "true positive" in " ".join(e2e.strip_tags(html).split())


def test_word_count_ignores_whitespace_shape(e2e: Any) -> None:
    assert e2e.words("  three   little   words  ") == 3
    assert e2e.words("") == 0


# ── Scenarios ────────────────────────────────────────────────────────────────
def test_every_scenario_has_both_follow_ups(e2e: Any) -> None:
    """A scenario without both is only testing the first pass, which is the
    part that already worked."""
    for name, scenario in e2e.SCENARIOS.items():
        assert scenario["alert"].get("title"), f"{name} has no alert title"
        assert scenario["midflight"].strip(), f"{name} has no mid-run telemetry"
        assert scenario["revision"].strip(), f"{name} has no post-close telemetry"


def test_default_scenario_exists(e2e: Any) -> None:
    assert e2e.DEFAULT_SCENARIO in e2e.SCENARIOS
