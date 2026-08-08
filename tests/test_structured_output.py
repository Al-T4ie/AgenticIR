"""Lenient parsing of model-produced structured output.

Written after a live run: a specialist returned `findings` as a JSON *string*
rather than an array, pydantic rejected the whole report, and an entire
specialist's work was lost to a formatting quirk. Providers differ here, so the
schemas parse leniently and let validation judge the parsed content.
"""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from app.graph.llm import coerce_json_list
from app.graph.nodes.containment import ContainmentPlan
from app.graph.nodes.specialist import SpecialistReport
from app.graph.nodes.supervisor import Plan


# ── The helper ───────────────────────────────────────────────────────────────
def test_json_encoded_list_is_parsed():
    assert coerce_json_list('[{"a": 1}]') == [{"a": 1}]


def test_real_list_passes_through_untouched():
    value = [{"a": 1}]
    assert coerce_json_list(value) is value


@pytest.mark.parametrize("value", ["not json at all", '{"a": 1}', '"a string"', "42", ""])
def test_non_list_input_is_left_for_validation_to_reject(value: str):
    """Only a JSON array is a plausible mis-encoding of a list. Anything else is
    returned unchanged so pydantic reports the real problem."""
    assert coerce_json_list(value) == value


def test_none_and_numbers_pass_through():
    assert coerce_json_list(None) is None
    assert coerce_json_list(7) == 7


# ── The schemas that carry model-filled lists ────────────────────────────────
def test_specialist_report_accepts_a_stringified_findings_list():
    payload = json.dumps([{"title": "Beaconing", "detail": "60s interval", "severity": "high"}])
    report = SpecialistReport.model_validate({"findings": payload, "gaps": ""})
    assert len(report.findings) == 1
    assert report.findings[0].title == "Beaconing"
    assert report.findings[0].severity == "high"


def test_plan_accepts_a_stringified_task_list():
    payload = json.dumps([{"specialist": "triage", "objective": "check the alert"}])
    plan = Plan.model_validate({"reasoning": "r", "tasks": payload})
    assert [t.specialist for t in plan.tasks] == ["triage"]


def test_containment_plan_accepts_a_stringified_action_list():
    payload = json.dumps(
        [{"action": "isolate_host", "target": "HOST-1", "justification": "C2 confirmed"}]
    )
    cp = ContainmentPlan.model_validate({"actions": payload, "reasoning": "r"})
    assert cp.actions[0].action == "isolate_host"


def test_well_formed_input_still_works():
    report = SpecialistReport.model_validate(
        {"findings": [{"title": "t", "detail": "d"}], "gaps": "none"}
    )
    assert len(report.findings) == 1


def test_garbage_still_fails_loudly():
    """Leniency must not become silence — a genuinely wrong shape still raises."""
    with pytest.raises(ValidationError):
        SpecialistReport.model_validate({"findings": "totally not a list"})
