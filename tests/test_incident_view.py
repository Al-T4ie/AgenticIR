"""Reading an incident: where it is in the graph, and what it touched.

Both views are derived, not stored — the stage from the timeline, the ATT&CK
placement from technique ids the model wrote. What matters is that neither
invents anything when the input is thin or wrong.
"""

from __future__ import annotations

from app.services import attack, slackmd, stages


def _timeline(*pairs: tuple[str, str]) -> list[dict[str, str]]:
    return [
        {"at": f"2026-08-08T21:{i:02d}:00+00:00", "actor": actor, "event": event}
        for i, (actor, event) in enumerate(pairs)
    ]


def _states(record):
    return {s["key"]: s["state"] for s in stages.derive(record)["steps"]}


# ── Where it is ──────────────────────────────────────────────────────────────
def test_a_running_incident_shows_the_stage_actually_in_flight():
    """`running` alone is ten seconds or two minutes of waiting. The point of
    the strip is telling those apart."""
    record = {
        "status": "running",
        "timeline": _timeline(
            ("intake", "opened"),
            ("supervisor", "Round 1: dispatched triage, enrichment"),
            ("triage", "Reported 3 finding(s)"),
        ),
    }
    state = _states(record)
    assert state["intake"] == "done"
    assert state["supervisor"] == "done"
    assert state["specialist"] == "done"
    # Specialists have reported, so the reviewer is what we are waiting on.
    assert state["critic"] == "active"
    assert state["containment"] == "pending"
    assert state["report"] == "pending"


def test_a_pending_approval_is_marked_as_waiting_on_a_human():
    record = {
        "status": "awaiting_approval",
        "timeline": _timeline(
            ("intake", "opened"),
            ("supervisor", "Round 1: dispatched triage"),
            ("triage", "Reported 2 finding(s)"),
            ("critic", "Review"),
            ("containment_planner", "Proposed 2"),
        ),
    }
    state = _states(record)
    assert state["containment"] == "done"
    assert state["approval"] == "waiting"
    assert state["execute"] == "pending"


def test_stages_never_reached_on_a_closed_incident_read_as_skipped():
    """Nothing needed approving, so the gate was not passed — it was bypassed.
    Showing it as still pending on a finished incident would be a lie."""
    record = {
        "status": "completed",
        "timeline": _timeline(
            ("intake", "opened"),
            ("supervisor", "Round 1: dispatched triage"),
            ("triage", "Reported 1 finding(s)"),
            ("critic", "Review"),
            ("containment_planner", "No actions proposed"),
            ("reporter", "Incident report generated"),
        ),
    }
    state = _states(record)
    assert state["approval"] == "skipped"
    assert state["execute"] == "skipped"
    assert state["report"] == "done"


def test_a_failure_marks_the_stage_it_died_in():
    record = {
        "status": "failed",
        "timeline": _timeline(("intake", "opened"), ("supervisor", "Round 1: dispatched triage")),
    }
    state = _states(record)
    assert state["supervisor"] == "failed"
    assert state["intake"] == "done"


def test_rounds_are_counted_across_the_whole_incident():
    record = {
        "status": "completed",
        "timeline": _timeline(
            ("intake", "opened"),
            ("supervisor", "Round 1: dispatched triage"),
            ("critic", "Review"),
            ("supervisor", "Round 2: dispatched enrichment"),
            ("critic", "Review"),
            ("supervisor", "Round 1: no further investigation needed"),
        ),
    }
    # The third supervisor entry dispatched nothing, so it is not a round.
    assert stages.derive(record)["rounds"] == 2


def test_a_revision_describes_the_current_pass_not_the_whole_history():
    """The first pass executed and reported. The reopened one has not got
    there yet, and showing execute as done would say it had."""
    record = {
        "status": "awaiting_approval",
        "timeline": _timeline(
            ("intake", "opened"),
            ("supervisor", "Round 1: dispatched triage"),
            ("triage", "Reported 2 finding(s)"),
            ("critic", "Review"),
            ("containment_planner", "Proposed 1"),
            ("human:analyst", "Approved 1 of 1"),
            ("executor", "Executed 1"),
            ("reporter", "Incident report generated"),
            # New information reopens it — the spine starts again.
            ("intake", "reopened"),
            ("supervisor", "Round 1: dispatched enrichment"),
            ("enrichment", "Reported 4 finding(s)"),
            ("critic", "Review"),
            ("containment_planner", "Proposed 2"),
        ),
    }
    result = stages.derive(record)
    state = {s["key"]: s["state"] for s in result["steps"]}

    assert result["revision"] == 1
    assert state["approval"] == "waiting"
    # Not "done" — the first pass ran these, this pass has not reached them.
    assert state["execute"] == "pending"
    assert state["report"] == "pending"
    assert result["rounds"] == 1
    assert result["total_rounds"] == 2


def test_specialist_detail_spans_every_pass():
    """The stage strip is about now; the run list is the whole record."""
    record = {
        "status": "completed",
        "timeline": _timeline(
            ("intake", "opened"),
            ("triage", "Reported 1 finding(s)"),
            ("intake", "reopened"),
            ("enrichment", "Reported 2 finding(s)"),
        ),
    }
    assert [s["specialist"] for s in stages.specialist_detail(record)] == ["triage", "enrichment"]


def test_an_empty_timeline_does_not_break_the_strip():
    state = _states({"status": "running", "timeline": []})
    assert state["intake"] == "active"
    assert all(v in {"active", "pending"} for v in state.values())


def test_the_fan_out_shows_which_specialist_is_still_out():
    """The whole reason for drawing the graph rather than a strip: two came
    back, one has not, and a single "Specialists" box cannot say that."""
    record = {
        "status": "running",
        "timeline": _timeline(
            ("intake", "opened"),
            ("supervisor", "Round 1: dispatched triage, enrichment, behavioral"),
            ("enrichment", "Reported 3 finding(s)"),
            ("behavioral", "Reported 2 finding(s)"),
        ),
    }
    state = stages.specialist_states(record)
    assert state["enrichment"]["state"] == "done"
    assert state["behavioral"]["state"] == "done"
    assert state["triage"]["state"] == "active"


def test_a_specialist_never_dispatched_is_distinct_from_one_still_running():
    record = {
        "status": "running",
        "timeline": _timeline(
            ("intake", "opened"),
            ("supervisor", "Round 1: dispatched enrichment"),
        ),
    }
    state = stages.specialist_states(record)
    assert state["enrichment"]["state"] == "active"
    assert state["triage"]["state"] == "unused"


def test_a_specialist_failure_is_carried_onto_the_graph():
    record = {
        "status": "completed",
        "timeline": _timeline(
            ("intake", "opened"),
            ("supervisor", "Round 1: dispatched behavioral"),
            ("behavioral", "Specialist failed: TimeoutError"),
        ),
    }
    assert stages.specialist_states(record)["behavioral"]["state"] == "failed"


def test_a_dispatch_that_never_reported_on_a_closed_incident_is_a_failure():
    """Nothing is in flight once the run is over, so an agent still marked
    active was dispatched into a run that ended without it."""
    record = {
        "status": "completed",
        "timeline": _timeline(
            ("intake", "opened"),
            ("supervisor", "Round 1: dispatched triage"),
            ("reporter", "Incident report generated"),
        ),
    }
    assert stages.specialist_states(record)["triage"]["state"] == "failed"


def test_specialist_runs_are_counted_within_the_current_pass():
    record = {
        "status": "completed",
        "timeline": _timeline(
            ("intake", "opened"),
            ("supervisor", "Round 1: dispatched enrichment"),
            ("enrichment", "Reported 1 finding(s)"),
            ("intake", "reopened"),
            ("supervisor", "Round 1: dispatched enrichment"),
            ("enrichment", "Reported 4 finding(s)"),
            ("supervisor", "Round 2: dispatched enrichment"),
            ("enrichment", "Reported 2 finding(s)"),
        ),
    }
    # Two runs this pass, not the three across the incident's whole life.
    assert stages.specialist_states(record)["enrichment"]["runs"] == 2


# ── What it touched ──────────────────────────────────────────────────────────
def _finding(*techniques: str, severity: str = "high", title: str = "f"):
    return {
        "title": title,
        "detail": "d",
        "severity": severity,
        "specialist": "behavioral",
        "round": 1,
        "mitre_techniques": list(techniques),
    }


def test_techniques_land_in_their_tactics_in_kill_chain_order():
    summary = attack.summarise(
        [_finding("T1566.001"), _finding("T1059.001"), _finding("T1071.001")]
    )
    observed = [lane["key"] for lane in summary["observed"]]
    assert observed == ["initial-access", "execution", "command-and-control"]
    assert summary["technique_count"] == 3
    assert summary["tactic_count"] == 3


def test_a_technique_in_several_tactics_appears_in_each():
    """T1053 is execution, persistence and privilege escalation. Showing it in
    one would understate how far the intrusion reached."""
    summary = attack.summarise([_finding("T1053.005")])
    hit = {lane["key"] for lane in summary["observed"]}
    assert hit == {"execution", "persistence", "privilege-escalation"}
    assert summary["technique_count"] == 1


def test_an_unlisted_sub_technique_falls_back_to_its_parent():
    """T1059.009 is still Command and Scripting Interpreter, still execution."""
    summary = attack.summarise([_finding("T1059.009")])
    assert [lane["key"] for lane in summary["observed"]] == ["execution"]
    technique = summary["techniques"][0]
    assert technique["exact"] is False
    assert "Command and Scripting" in technique["name"]


def test_an_unknown_technique_is_reported_not_guessed():
    """A confidently wrong tactic is worse than an honest gap."""
    summary = attack.summarise([_finding("T9999")])
    assert summary["observed"] == []
    assert [u["label"] for u in summary["unmapped"]] == ["T9999"]


def test_ids_are_pulled_out_of_whatever_the_model_wrote():
    summary = attack.summarise([_finding("t1059.001", "T1071.001 (Web Protocols)")])
    assert {t["id"] for t in summary["techniques"]} == {"T1059.001", "T1071.001"}


def test_a_citation_with_no_id_in_it_is_unmapped_not_dropped():
    summary = attack.summarise([_finding("PowerShell abuse")])
    assert summary["unmapped"] and summary["observed"] == []


def test_each_technique_keeps_the_findings_that_cited_it():
    """This is what makes the view diggable rather than just a count."""
    a = _finding("T1071.001", title="beaconing")
    b = _finding("T1071.001", title="second observation")
    summary = attack.summarise([a, b])
    technique = summary["techniques"][0]
    assert [f["title"] for f in technique["findings"]] == ["beaconing", "second observation"]


def test_a_tactic_takes_the_worst_severity_under_it():
    summary = attack.summarise(
        [_finding("T1071.001", severity="low"), _finding("T1105", severity="critical")]
    )
    c2 = next(lane for lane in summary["observed"] if lane["key"] == "command-and-control")
    assert c2["severity"] == "critical"


def test_no_findings_is_empty_not_broken():
    summary = attack.summarise([])
    assert summary["empty"] is True
    assert summary["observed"] == []
    # Every tactic is still present so the chain renders with all 14 columns.
    assert len(summary["lanes"]) == len(attack.TACTICS)


# ── Reports are Slack markdown, the dashboard is HTML ────────────────────────
def test_the_dialect_the_report_prompt_actually_produces():
    html = slackmd.to_html(
        "*inconclusive · high · 91% confidence*\n"
        "Encoded PowerShell spawned by Outlook.\n"
        "• `-Enc` value truncated to 8 chars\n"
        "• Falcon verdict not reported\n"
        "*Do:* Pull the full command line."
    )
    assert "<strong>inconclusive · high · 91% confidence</strong>" in html
    assert "<code>-Enc</code>" in html
    assert html.count("<li>") == 2
    assert "<ul>" in html
    # No stray markup characters left for the reader to trip over.
    assert "*" not in html and "`" not in html


def test_report_text_cannot_inject_markup():
    """A report quotes attacker-controlled strings — payloads, filenames, URLs.
    Escaping happens before any markup is introduced, so it cannot become HTML."""
    html = slackmd.to_html("Payload was <script>alert(1)</script> on *HOST-1*")
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    # Legitimate emphasis still renders.
    assert "<strong>HOST-1</strong>" in html


def test_an_asterisk_inside_a_word_is_not_emphasis():
    html = slackmd.to_html("The glob was C:\\Users\\*\\AppData and 2*3 is 6")
    assert "<strong>" not in html


def test_blank_input_renders_nothing():
    assert slackmd.to_html("") == ""
    assert slackmd.to_html("   \n  ") == ""


def test_numbered_and_dashed_lines_are_lists_too():
    html = slackmd.to_html("1. first\n2. second\n\n- third")
    assert html.count("<ul>") == 2
    assert html.count("<li>") == 3


def test_every_catalogued_technique_maps_to_a_real_tactic():
    """A typo in the table would silently drop a technique out of the view."""
    known = {key for key, _ in attack.TACTICS}
    for tid, (name, tactics) in attack.TECHNIQUES.items():
        assert name, f"{tid} has no name"
        assert tactics, f"{tid} has no tactics"
        assert set(tactics) <= known, f"{tid} references an unknown tactic"
