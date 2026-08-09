#!/usr/bin/env python3
"""Drive one incident end to end and judge whether the deployment is fit to use.

`smoke-test.sh` answers "is it up". That is not the same question as "would I
hand this to an on-call analyst tonight", and the gap between the two is where
this product's real failure modes live: a report that contradicts the record it
was written from, a follow-up that returns an error for telemetry it in fact
stored, a stage strip that says containment already executed on an incident
that is about to execute it again. Every one of those passes a health check.

So this walks a single realistic incident through every surface a responder
touches — SIEM intake, Slack narration, mid-flight telemetry, the human
approval gate, a revision after close, both HTTP views, the channel sweep — and
asserts the things that were actually wrong at some point, not the things that
are easy to assert.

Checks are graded. A BLOCKER means the product is not fit to ship; a WARN means
it works but something is degraded or could not be proven from outside. The
exit code follows blockers only, so an unattended run is a usable gate.

    BASE_URL=https://air.example.com API_KEY=... \
    WEBHOOK_TOKEN=... SLACK_BOT_TOKEN=xoxb-... SLACK_CHANNEL=C0… \
      python3 infra/scripts/e2e_scenario.py

Everything except BASE_URL and API_KEY is optional; each missing credential
turns its phase into a WARN ("could not verify") rather than a failure, so the
harness still runs against a bare local stack.

Stdlib only, deliberately — it has to run from a CI container, a laptop and the
app image itself without a dependency being the reason a release is not tested.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

# ── Scenarios ────────────────────────────────────────────────────────────────
# Each scenario is one alert plus the telemetry that arrives after it, because
# the interesting behaviour is not the first pass — it is what happens when a
# second source contradicts or extends the first while the graph is mid-flight.

SCENARIOS: dict[str, dict[str, Any]] = {
    "ransomware-precursor": {
        "title": "Encoded PowerShell + credential access on a finance workstation",
        "alert": {
            "title": "EDR: encoded PowerShell spawned by Outlook",
            "severity": "high",
            "source_product": "CrowdStrike Falcon",
            "host": "FIN-WS-04",
            "src_ip": "10.4.2.19",
            "user": "j.okafor@example.com",
            "process": (
                "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"
            ),
            "parent_process": "OUTLOOK.EXE",
            "detail": (
                "Base64 PowerShell launched from an Outlook child process, followed by "
                "repeating 60s TLS callouts to 198.51.100.77:443. LSASS handle opened by "
                "the same process tree 90 seconds later."
            ),
        },
        # Arrives while the first pass is still running — proves queueing.
        "midflight": (
            "Zscaler: FIN-WS-04 resolved cdn-update-delivery[.]net (registered 6 days ago, "
            "Namecheap) 40s before the first callout. 4.2 MB uploaded over the session — "
            "the host's 30-day upload median is 60 KB."
        ),
        # Arrives after the incident is closed — proves revision.
        "revision": (
            "Entra ID: the same user's refresh token was replayed from 198.51.100.77 at "
            "02:14 UTC and enrolled a new TOTP authenticator. Two other finance "
            "workstations (FIN-WS-07, FIN-WS-11) contacted the same host within the hour."
        ),
    },
    "phishing-false-positive": {
        "title": "Reported phish that is a legitimate vendor mailshot",
        "alert": {
            "title": "User-reported phishing: DocuSign envelope",
            "severity": "medium",
            "source_product": "Proofpoint TRAP",
            "user": "a.mensah@example.com",
            "sender": "dse@docusign.net",
            "detail": (
                "User reported a DocuSign envelope as phishing. Link resolves to "
                "eu.docusign.net. SPF pass, DKIM pass, DMARC aligned."
            ),
        },
        "midflight": (
            "Mail gateway: 214 recipients in the same tenant received the identical "
            "envelope in the same minute; none of the links differ."
        ),
        "revision": (
            "Procurement confirmed the contract-renewal mailshot was scheduled for that "
            "morning by the vendor's account team."
        ),
    },
    # Modelled on the publicly reported UNC6040 / ShinyHunters SaaS campaign:
    # vishing the user into authorising a look-alike connected app, bulk export
    # over the vendor's own API, then extortion. Nothing touches an endpoint, so
    # it is the scenario that fails if the platform only reasons about EDR.
    "shinyhunters-saas": {
        "title": "Vished OAuth grant into bulk CRM export and extortion",
        "alert": {
            "title": "Unrecognised connected app performing bulk CRM export",
            "severity": "critical",
            "source_product": "Salesforce Shield Event Monitoring",
            "user": "r.delacruz@example.com",
            "platform": "Salesforce (production, customer PII and pipeline)",
            "connected_app": "'Data Loader' — consumer key not in the approved app inventory",
            "src_ip": "185.65.135.42 (AS39351 Mullvad VPN, Amsterdam)",
            "detail": (
                "A connected app named 'Data Loader' was authorised at 12:58 UTC from a "
                "Mullvad exit node, then exported 1,204,719 records across Account, "
                "Contact, Opportunity, Case and Attachment in 43 minutes via Bulk API 2.0 "
                "— about 287x the tenant's daily baseline. The authorising user says a "
                "caller claiming to be internal IT talked her through the approval and "
                "read out a verification code. Her normal egress is the Manila corporate "
                "ASN. No endpoint alert fired; the whole chain is SaaS-native."
            ),
        },
        "midflight": (
            "Okta: the same user completed an MFA push at 12:57 UTC from 185.65.135.42, "
            "13 seconds after a push she declined from the same IP. Two other Sales Ops "
            "users received declined pushes from the same ASN within the hour. The "
            "helpdesk logged three calls that morning from a caller asking to 'confirm "
            "which staff have Salesforce admin'."
        ),
        "revision": (
            "An extortion email arrived at legal@example.com from a ProtonMail address "
            "quoting the exact export count (1,204,719) and a sample of 20 real Account "
            "records. It threatens publication on a leak site in 72 hours and names the "
            "group. Salesforce confirms the connected app's refresh token is still valid "
            "and was used again 20 minutes ago."
        ),
    },
}

DEFAULT_SCENARIO = "ransomware-precursor"

BLOCKER, WARN, INFO = "blocker", "warn", "info"


# ── Result collection ────────────────────────────────────────────────────────
@dataclass
class Check:
    phase: str
    name: str
    ok: bool
    grade: str
    detail: str = ""


@dataclass
class Report:
    checks: list[Check] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)
    started: float = field(default_factory=time.time)

    def check(
        self,
        phase: str,
        name: str,
        ok: bool,
        *,
        grade: str = BLOCKER,
        detail: str = "",
        on_fail: str = "",
    ) -> bool:
        """Record one check. `detail` is evidence either way; `on_fail` explains
        a failure and is suppressed when the check passes — printing "no edited
        message seen yet" next to a green tick is worse than printing nothing.
        """
        shown = detail if ok else (on_fail or detail)
        self.checks.append(Check(phase, name, ok, grade, shown))
        mark = "✓" if ok else ("✗" if grade == BLOCKER else "!")
        print(f"  {mark} {name}{f' — {shown}' if shown else ''}", flush=True)
        return ok

    def note(self, phase: str, name: str, detail: str) -> None:
        self.checks.append(Check(phase, name, True, INFO, detail))
        print(f"  · {name} — {detail}", flush=True)

    def blockers(self) -> list[Check]:
        return [c for c in self.checks if not c.ok and c.grade == BLOCKER]

    def warnings(self) -> list[Check]:
        return [c for c in self.checks if not c.ok and c.grade == WARN]


# ── HTTP ─────────────────────────────────────────────────────────────────────
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Report the redirect instead of following it.

    "Does /ui bounce an unauthenticated caller to the login page" is the check;
    a client that follows the 303 answers "the login page renders", which is a
    different and much weaker statement.
    """

    def redirect_request(self, *_a: Any, **_k: Any) -> None:
        return None


class Http:
    def __init__(self, base: str, api_key: str, timeout: int = 60) -> None:
        self.base = base.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.ctx = ssl.create_default_context()
        self.opener = urllib.request.build_opener(
            _NoRedirect, urllib.request.HTTPSHandler(context=self.ctx)
        )

    def raw(
        self,
        path: str,
        *,
        method: str = "GET",
        payload: Any = None,
        headers: dict[str, str] | None = None,
        auth: bool = True,
        timeout: int | None = None,
    ) -> tuple[int, str]:
        url = path if path.startswith("http") else self.base + path
        hdrs = dict(headers or {})
        if auth and self.api_key:
            hdrs.setdefault("X-API-Key", self.api_key)
        data = None
        if payload is not None:
            data = json.dumps(payload).encode()
            hdrs.setdefault("Content-Type", "application/json")
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        try:
            with self.opener.open(req, timeout=timeout or self.timeout) as r:
                return r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8", "replace")
        except Exception as exc:  # noqa: BLE001 — a dead socket is a result, not a crash
            return 0, str(exc)

    def json(self, path: str, **kw: Any) -> tuple[int, Any]:
        status, body = self.raw(path, **kw)
        try:
            return status, json.loads(body)
        except Exception:  # noqa: BLE001
            return status, body

    def code(self, path: str, **kw: Any) -> int:
        return self.raw(path, **kw)[0]


class Slack:
    """Just enough Slack to observe what the app did. Never posts as a human."""

    def __init__(self, token: str) -> None:
        self.token = token
        self.ctx = ssl.create_default_context()

    def call(self, method: str, **params: Any) -> dict[str, Any]:
        url = f"https://slack.com/api/{method}?" + urllib.parse.urlencode(
            {k: v for k, v in params.items() if v is not None}
        )
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {self.token}"})
        try:
            with urllib.request.urlopen(req, timeout=30, context=self.ctx) as r:
                return json.load(r)
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": str(exc)}


# ── Helpers ──────────────────────────────────────────────────────────────────
def wait_for(
    http: Http,
    incident_id: str,
    want: set[str],
    *,
    timeout: int,
    label: str,
) -> dict[str, Any]:
    """Poll one incident until its status lands in `want` or time runs out."""
    deadline = time.time() + timeout
    record: dict[str, Any] = {}
    last = ""
    while time.time() < deadline:
        status_code, record = http.json(f"/v1/incidents/{incident_id}")
        if status_code != 200 or not isinstance(record, dict):
            time.sleep(5)
            continue
        status = str(record.get("status", ""))
        if status != last:
            elapsed = int(timeout - (deadline - time.time()))
            print(f"    {label}: {status} ({elapsed}s)", flush=True)
            last = status
        if status in want:
            return record
        time.sleep(5)
    return record if isinstance(record, dict) else {}


def words(text: str) -> int:
    return len(re.findall(r"\S+", text or ""))


def strip_tags(html: str) -> str:
    return re.sub(r"<[^>]+>", " ", html)


# ── Phases ───────────────────────────────────────────────────────────────────
def phase_surface(http: Http, rep: Report) -> None:
    print("\n▸ 1. Surface — the contract an unauthenticated caller sees")
    p = "surface"
    rep.check(p, "GET /health is 200", http.code("/health", auth=False) == 200)
    rep.check(p, "GET /ready is 200", http.code("/ready", auth=False) == 200)
    rep.check(p, "GET /docs is 200", http.code("/docs", auth=False) == 200, grade=WARN)
    rep.check(p, "GET /ui redirects to login", http.code("/ui", auth=False) == 303)
    rep.check(
        p, "GET /v1/incidents unauthenticated is 401", http.code("/v1/incidents", auth=False) == 401
    )
    rep.check(
        p,
        "GET /v1/incidents with a wrong key is 401",
        http.code("/v1/incidents", auth=False, headers={"X-API-Key": "wrong"}) == 401,
    )
    rep.check(
        p,
        "POST /webhooks/alert unauthenticated is 401",
        http.code("/webhooks/alert", method="POST", payload={}, auth=False) == 401,
    )
    rep.check(
        p,
        "POST /slack/events unsigned is 401",
        http.code("/slack/events", method="POST", payload={}, auth=False) == 401,
        detail="signature verification is the only control on a public endpoint",
    )
    rep.check(p, "GET /v1/incidents with the key is 200", http.code("/v1/incidents?limit=1") == 200)
    rep.check(
        p,
        "POST /v1/incidents with an empty body is 422",
        http.code("/v1/incidents", method="POST", payload={}) == 422,
    )


def phase_intake(http: Http, rep: Report, scenario: dict[str, Any], webhook_token: str) -> str:
    print("\n▸ 2. Intake — a SIEM posts an alert nobody is watching for")
    p = "intake"
    if not webhook_token:
        rep.check(
            p,
            "SIEM webhook intake",
            False,
            grade=WARN,
            on_fail="WEBHOOK_TOKEN unset — falling back to the authenticated API",
        )
        status, body = http.json(
            "/v1/incidents",
            method="POST",
            payload={"source": "e2e", "alert": scenario["alert"]},
        )
    else:
        status, body = http.json(
            "/webhooks/alert",
            method="POST",
            auth=False,
            headers={"Authorization": f"Bearer {webhook_token}"},
            payload={"source": "e2e-siem", "alert": scenario["alert"]},
        )
        rep.check(p, "POST /webhooks/alert is accepted", status == 202, detail=f"HTTP {status}")

    incident_id = str((body or {}).get("incident_id", "")) if isinstance(body, dict) else ""
    rep.check(
        p, "an incident id came back", bool(incident_id), detail=incident_id or str(body)[:160]
    )
    if incident_id:
        rep.facts["incident_id"] = incident_id
    return incident_id


def phase_narration(
    http: Http, slack: Slack | None, rep: Report, incident_id: str, channel: str
) -> None:
    print("\n▸ 3. Narration — the responder learns about it without being told")
    p = "narration"

    # The thread has to be adopted before the run finishes, or an alert that
    # arrived from a SIEM stays silent in Slack until the final report — which
    # is precisely when narration stops being useful.
    thread_ts, record = "", {}
    deadline = time.time() + 120
    while time.time() < deadline:
        _, record = http.json(f"/v1/incidents/{incident_id}")
        thread_ts = str((record or {}).get("slack_thread_ts") or "")
        if thread_ts:
            break
        time.sleep(5)

    if not (slack and channel):
        rep.check(
            p,
            "Slack narration",
            False,
            grade=WARN,
            on_fail="SLACK_BOT_TOKEN/SLACK_CHANNEL unset — not verified",
        )
        return

    rep.check(p, "a thread was opened for the alert", bool(thread_ts), detail=thread_ts or "none")
    if not thread_ts:
        return

    # Let a couple of node transitions land so there is something to have edited.
    time.sleep(45)
    replies = slack.call("conversations.replies", channel=channel, ts=thread_ts, limit=50)
    msgs = replies.get("messages", []) if replies.get("ok") else []
    rep.check(p, "the thread is readable", bool(msgs), grade=WARN, detail=replies.get("error", ""))

    edited = [m for m in msgs if m.get("edited")]
    rep.facts["thread_messages"] = len(msgs)
    rep.check(
        p,
        "progress is edited in place, not re-posted",
        len(msgs) <= 6,
        detail=f"{len(msgs)} messages in the thread, {len(edited)} edited",
    )
    rep.check(
        p,
        "at least one message is being updated live",
        bool(edited),
        grade=WARN,
        on_fail="no edited message seen yet — the run may still be on its first node",
    )


def phase_midflight(http: Http, rep: Report, incident_id: str, note: str) -> None:
    print("\n▸ 4. Mid-flight telemetry — a second source arrives while it runs")
    p = "midflight"
    status, body = http.json(
        f"/v1/incidents/{incident_id}/follow-up",
        method="POST",
        payload={"note": note, "reported_by": "e2e-harness"},
    )
    outcome = str((body or {}).get("status", "")) if isinstance(body, dict) else ""

    # Returning 409 here was the bug worth guarding: it told the caller their
    # telemetry had been rejected when the note had in fact been stored, so an
    # integration would retry or drop data that was already accepted.
    rep.check(
        p,
        "telemetry sent mid-run is accepted, not rejected",
        status == 202,
        detail=f"HTTP {status} {outcome}",
    )
    rep.check(
        p,
        "the response says whether it was applied or queued",
        isinstance(body, dict) and "applied" in body,
        detail=f"status={outcome} applied={(body or {}).get('applied')}",
    )
    rep.facts["midflight_outcome"] = outcome


def phase_gate(
    http: Http, rep: Report, incident_id: str, timeout: int, max_rounds: int
) -> dict[str, Any]:
    print("\n▸ 5. Investigation — does it reach a decision, and is it worth reading")
    p = "investigation"
    record = wait_for(
        http,
        incident_id,
        {"awaiting_approval", "completed", "failed"},
        timeout=timeout,
        label="pass 1",
    )
    status = str(record.get("status", "none"))
    rep.check(
        p,
        "the run reached a decision point",
        status in {"awaiting_approval", "completed"},
        detail=status,
    )
    if status == "failed":
        return record

    findings = record.get("findings", []) or []
    rep.check(
        p, "the investigation produced findings", bool(findings), detail=f"{len(findings)} findings"
    )

    # Concision is a product requirement here, not a style preference: an
    # unbounded finding list is what made the critic downgrade a true positive
    # after more evidence arrived, and it is what nobody reads at 3am.
    per_specialist: dict[str, int] = {}
    for f in findings:
        key = f"{f.get('specialist', '?')}/r{f.get('round', '?')}"
        per_specialist[key] = per_specialist.get(key, 0) + 1
    worst = max(per_specialist.values(), default=0)
    rep.check(
        p,
        "no specialist floods a round with findings",
        worst <= 4,
        detail=f"worst round: {worst} findings ({max(per_specialist, key=per_specialist.get, default='—')})",
    )

    # The record carries no round counter; rounds are the supervisor's dispatch
    # events in the current pass, the same way the dashboard derives them.
    entries = record.get("timeline", []) or []
    starts = [i for i, e in enumerate(entries) if str(e.get("actor")) == "intake"]
    current = entries[starts[-1] :] if starts else entries
    rounds = sum(
        1
        for e in current
        if str(e.get("actor")) == "supervisor" and "dispatched" in str(e.get("event", ""))
    )
    rep.check(
        p, "the round cap is respected", rounds <= max_rounds, detail=f"{rounds} of {max_rounds}"
    )

    verdict = str(record.get("verdict", ""))
    rep.check(
        p,
        "a verdict was reached",
        bool(verdict) and verdict != "unknown",
        detail=verdict,
        grade=WARN,
    )
    rep.facts["verdict_pass1"] = verdict
    rep.facts["findings_pass1"] = len(findings)

    questions = record.get("open_questions", []) or []
    rep.note(
        p,
        "open questions raised for the responder",
        f"{len(questions)}: {'; '.join(questions[:2])[:140]}",
    )
    return record


def approve(http: Http, incident_id: str, record: dict[str, Any], why: str) -> tuple[int, int]:
    """Approve everything pending on an incident. Returns (HTTP status, count)."""
    pending = [a for a in record.get("containment_actions", []) if a.get("requires_approval")]
    status, _ = http.json(
        f"/v1/incidents/{incident_id}/approve",
        method="POST",
        payload={
            "approved_all": True,
            "approved_actions": [a["action"] for a in pending],
            "approver": "e2e-harness",
            "note": why,
        },
    )
    return status, len(pending)


def settle(
    http: Http,
    rep: Report,
    incident_id: str,
    timeout: int,
    label: str,
    *,
    phase: str = "approval",
    max_gates: int = 3,
) -> dict[str, Any]:
    """Drive an incident to a terminal state, approving every gate it stops at.

    One approval does not mean one gate. Draining telemetry that arrived
    mid-run produces a revision, and a revision that proposes containment must
    ask again — the alternative is executing actions a human never saw. Waiting
    only for `completed` reads that correct behaviour as a hang.
    """
    for gate in range(max_gates):
        record = wait_for(
            http,
            incident_id,
            {"completed", "failed", "awaiting_approval"},
            timeout=timeout,
            label=label,
        )
        if str(record.get("status")) != "awaiting_approval":
            return record
        status, count = approve(http, incident_id, record, f"approved by the {label} scenario")
        rep.note(
            phase,
            f"gate {gate + 2} reached",
            f"a revision proposed {count} more action(s) — approved, HTTP {status}",
        )
    return wait_for(http, incident_id, {"completed", "failed"}, timeout=timeout, label=label)


def phase_approval(
    http: Http, rep: Report, incident_id: str, record: dict[str, Any], timeout: int
) -> dict[str, Any]:
    print("\n▸ 6. Human gate — the decision a machine does not get to make")
    p = "approval"
    if str(record.get("status")) != "awaiting_approval":
        rep.check(
            p,
            "containment paused for a human",
            False,
            grade=WARN,
            on_fail=f"status was {record.get('status')} — nothing needed approving on this run",
        )
        return record

    pending = [a for a in record.get("containment_actions", []) if a.get("requires_approval")]
    rep.check(
        p,
        "the actions awaiting approval are enumerated",
        bool(pending),
        detail=f"{len(pending)} action(s)",
    )
    rep.note(p, "proposed", "; ".join(str(a.get("action", ""))[:60] for a in pending[:3]) or "none")

    status, _count = approve(http, incident_id, record, "approved by the end-to-end scenario")
    rep.check(p, "the approval is accepted", status == 200, detail=f"HTTP {status}")

    after = settle(http, rep, incident_id, timeout, "after approval")
    rep.check(
        p,
        "the run resumes and finishes",
        str(after.get("status")) == "completed",
        detail=str(after.get("status")),
    )

    # The queued mid-flight note has to be drained here, and as one revision —
    # not one revision per queued note, which would re-run the whole graph twice
    # for two lines of telemetry that arrived a second apart.
    findings_now = len(after.get("findings", []) or [])
    rep.check(
        p,
        "queued telemetry was folded in on resume",
        findings_now >= rep.facts.get("findings_pass1", 0),
        grade=WARN,
        detail=f"findings {rep.facts.get('findings_pass1', 0)} → {findings_now}",
    )
    rep.facts["findings_after_approval"] = findings_now
    return after


def phase_revision(
    http: Http, rep: Report, incident_id: str, note: str, timeout: int
) -> dict[str, Any]:
    print("\n▸ 7. Revision — new information about an incident already closed")
    p = "revision"
    before = rep.facts.get("findings_after_approval", 0)

    status, body = http.json(
        f"/v1/incidents/{incident_id}/follow-up",
        method="POST",
        payload={"note": note, "reported_by": "e2e-harness"},
    )
    outcome = str((body or {}).get("status", "")) if isinstance(body, dict) else ""
    rep.check(
        p,
        "a closed incident accepts new information",
        status == 202,
        detail=f"HTTP {status} {outcome}",
    )
    rep.check(
        p,
        "it re-opens immediately rather than queueing",
        outcome == "revising",
        grade=WARN,
        detail=outcome,
    )

    after = settle(http, rep, incident_id, timeout, "revision", phase="revision")
    rep.check(
        p,
        "the revision finishes",
        str(after.get("status")) == "completed",
        detail=str(after.get("status")),
    )
    now = len(after.get("findings", []) or [])
    rep.check(
        p,
        "the revision changed the record",
        now != before or str(after.get("verdict")) != rep.facts.get("verdict_pass1"),
        grade=WARN,
        detail=f"findings {before} → {now}, verdict {rep.facts.get('verdict_pass1')} → {after.get('verdict')}",
    )
    rep.facts["verdict_final"] = str(after.get("verdict", ""))
    rep.facts["findings_final"] = now
    return after


def phase_views(
    http: Http, rep: Report, incident_id: str, record: dict[str, Any], api_key: str
) -> None:
    print("\n▸ 8. HTTP views — what a responder actually looks at")
    p = "views"
    cookie = {"Cookie": f"agenticir_key={urllib.parse.quote(api_key)}"}

    status, page = http.raw(f"/ui/incidents/{incident_id}", headers=cookie, auth=False)
    rep.check(p, "the incident page renders", status == 200, detail=f"HTTP {status}")
    if status == 200:
        rep.check(p, "the agent graph is drawn", 'class="agraph"' in page)
        rep.check(p, "the timeline chart is drawn", 'class="gantt"' in page, grade=WARN)
        rep.check(p, "the ATT&CK chain is shown", 'class="chain"' in page and "ATT&amp;CK" in page)
        rep.check(
            p,
            "the page is self-contained (no external assets)",
            not re.search(r'(?:\bsrc="|<link[^>]+href=")https?://', page),
            on_fail="a CDN reference would break behind a strict CSP",
        )
        # Every technique a specialist cites should resolve to a name. One that
        # does not is shown to the responder as a bare `T####`, which is the
        # one thing an ATT&CK view exists to avoid.
        rep.check(
            p,
            "every cited ATT&CK technique resolves",
            "not in the local ATT&amp;CK catalogue" not in page,
            grade=WARN,
            on_fail="a cited technique is missing from app/services/attack.py",
        )

    status, page = http.raw(f"/ui/incidents/{incident_id}/report", headers=cookie, auth=False)
    rep.check(p, "the report page renders", status == 200, detail=f"HTTP {status}")
    if status != 200:
        return

    text = strip_tags(page)

    # The header used to be written by the model, which let a report say
    # "Likely malicious · high · 80%" over a record that said inconclusive. It
    # is now composed from the record, so the two cannot drift.
    verdict = str(record.get("verdict", "")).replace("_", " ")
    rep.check(
        p,
        "the report headline matches the stored verdict",
        not verdict or verdict.lower() in text.lower(),
        detail=f"record says '{verdict}'",
    )

    body = str(record.get("report", ""))
    rep.check(
        p,
        "the report is short enough to be read",
        words(body) <= 160,
        grade=WARN,
        detail=f"{words(body)} words",
    )
    rep.check(
        p,
        "Slack markdown is rendered, not printed",
        not re.search(r"\w\*\w|\s\*[A-Za-z][^*\n]{2,}\*\s", text),
        grade=WARN,
        on_fail="raw asterisks or backticks visible in the rendered page",
    )
    # The published artefact and the record it was written from have drifted
    # before. Counting is a cheap way to notice it again.
    n = len(record.get("findings", []) or [])
    rep.check(
        p,
        "the report page shows the record's findings",
        f"Findings ({n})" in text,
        detail=f"record has {n}",
    )
    executed = record.get("executed_actions", []) or []
    if executed:
        rep.check(
            p,
            "executed containment appears in the report",
            all(str(a.get("action", ""))[:40] in text for a in executed[:3]),
            grade=WARN,
            detail=f"{len(executed)} action(s) executed",
        )


def phase_channel(
    http: Http, slack: Slack | None, rep: Report, channel: str, wait_human: int
) -> None:
    print("\n▸ 9. Channel awareness — the sweep that nobody triggers")
    p = "channel"

    status, body = http.json("/v1/slack/poll", method="POST", payload={}, timeout=120)
    rep.check(p, "an out-of-band sweep runs", status == 200, detail=f"HTTP {status}")
    if isinstance(body, dict):
        rep.note(p, "sweep result", json.dumps(body)[:200])

    if not (slack and channel):
        rep.check(
            p, "channel reads", False, grade=WARN, on_fail="no Slack token — sweep mechanics only"
        )
        return

    if wait_human <= 0:
        rep.check(
            p,
            "a human line in the channel is picked up",
            False,
            grade=WARN,
            on_fail="skipped — rerun with --wait-human 300 and type a line in the channel",
        )
        return

    print(f"    post a line in the channel now — waiting up to {wait_human}s", flush=True)
    deadline, seen = time.time() + wait_human, False
    before = slack.call("conversations.history", channel=channel, limit=1)
    cursor = (before.get("messages") or [{}])[0].get("ts", "0")
    while time.time() < deadline:
        time.sleep(20)
        hist = slack.call("conversations.history", channel=channel, oldest=cursor, limit=20)
        human = [m for m in hist.get("messages", []) if not m.get("bot_id") and not m.get("app_id")]
        if human:
            seen = True
            break
    rep.check(
        p,
        "a human line arrived to sweep",
        seen,
        grade=WARN,
        on_fail="none posted during the window",
    )
    if seen:
        http.json("/v1/slack/poll", method="POST", payload={}, timeout=120)
        rep.note(p, "swept", "check the channel for the bot's reply")


def series(metrics: str, name: str) -> float:
    """Sum every labelled sample of one metric in a Prometheus exposition.

    Anchored on the sample line, not on the name appearing somewhere. `# HELP`
    and `# TYPE` comments contain the name too, and a grep that matches those
    reports a counter as present when nothing has ever incremented it — which
    is exactly how a deploy once got reported as verified when it had not
    swapped.
    """
    total = 0.0
    for m in re.finditer(rf"^{re.escape(name)}(?:\{{[^}}]*\}})? ([0-9.e+-]+)$", metrics, re.M):
        with contextlib.suppress(ValueError):
            total += float(m.group(1))
    return total


def phase_ops(http: Http, rep: Report, *, ran_incident: bool) -> None:
    print("\n▸ 10. Operations — what the platform says about itself")
    p = "ops"
    status, metrics = http.raw("/metrics", auth=False, timeout=30)
    if not rep.check(p, "metrics are exposed", status == 200, grade=WARN, detail=f"HTTP {status}"):
        return

    started = series(metrics, "process_start_time_seconds")
    uptime = time.time() - started if started else 0
    rep.note(p, "process uptime", f"{uptime / 60:.0f} min")

    # Counters are per-process and reset on deploy, so "zero runs" on a
    # ten-minute-old container is a fact about the restart, not a defect. It is
    # only evidence of anything if this harness just drove a run through it.
    runs = series(metrics, "agenticir_runs_started_total")
    if ran_incident:
        rep.check(
            p,
            "this run was counted",
            runs > 0,
            grade=WARN,
            detail=f"{runs:.0f} since boot",
            on_fail="zero — metrics are not wired to the graph",
        )
    else:
        rep.note(p, "runs since boot", f"{runs:.0f}")

    cycles = series(metrics, "agenticir_slack_poll_cycles_total")
    rep.check(
        p,
        "the channel poller is sweeping",
        cycles > 0,
        grade=WARN,
        detail=f"{cycles:.0f} cycles since boot"
        if cycles
        else "no sweeps recorded — poller may be disabled",
    )

    # Count the failure label, never "everything that isn't success". Guessing
    # the vocabulary made this read 30 successful calls as 30 failures, and the
    # same mistake in the other direction would hide real ones: `app/graph/llm.py`
    # labels outcomes `ok` and `error`.
    by_outcome: dict[str, float] = {}
    for m in re.finditer(
        r'^agenticir_llm_calls_total\{[^}]*outcome="(\w+)"[^}]*\} ([0-9.e+-]+)$', metrics, re.M
    ):
        with contextlib.suppress(ValueError):
            by_outcome[m.group(1)] = by_outcome.get(m.group(1), 0.0) + float(m.group(2))

    errors = by_outcome.get("error", 0.0)
    ok = by_outcome.get("ok", 0.0)
    unknown = sorted(set(by_outcome) - {"ok", "error"})
    rep.check(
        p,
        "no LLM call failures accumulating",
        errors == 0,
        grade=WARN,
        detail=f"{ok:.0f} succeeded, none failed",
        on_fail=f"{errors:.0f} failed of {ok + errors:.0f}",
    )
    if unknown:
        # A label this harness does not recognise is silently uncounted, which
        # is how a failure mode goes unnoticed for a release.
        rep.check(
            p,
            "every LLM outcome label is accounted for",
            False,
            grade=WARN,
            on_fail=f"unrecognised outcome(s): {', '.join(unknown)}",
        )

    rep.facts["uptime_min"] = round(uptime / 60, 1)


# ── Entry point ──────────────────────────────────────────────────────────────
def summarise(rep: Report, incident_id: str, base: str) -> int:
    blockers, warnings = rep.blockers(), rep.warnings()
    total = len([c for c in rep.checks if c.grade != INFO])
    passed = len([c for c in rep.checks if c.ok and c.grade != INFO])

    print("\n" + "─" * 78)
    print(f"  {passed}/{total} checks passed in {(time.time() - rep.started) / 60:.1f} min")
    if incident_id:
        print(f"  incident   {incident_id}")
        print(f"  timeline   {base}/ui/incidents/{incident_id}")
        print(f"  report     {base}/ui/incidents/{incident_id}/report")
    for key, value in rep.facts.items():
        if key != "incident_id":
            print(f"  {key:<24} {value}")

    if blockers:
        print(f"\n  ✗ {len(blockers)} BLOCKER(S) — not fit to ship:")
        for c in blockers:
            print(f"      [{c.phase}] {c.name}{' — ' + c.detail if c.detail else ''}")
    if warnings:
        print(f"\n  ! {len(warnings)} warning(s) — works, but degraded or unverified:")
        for c in warnings:
            print(f"      [{c.phase}] {c.name}{' — ' + c.detail if c.detail else ''}")
    if not blockers and not warnings:
        print("\n  ✓ every check passed")
    print("─" * 78)
    return 1 if blockers else 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--scenario", default=DEFAULT_SCENARIO, choices=sorted(SCENARIOS))
    ap.add_argument(
        "--timeout", type=int, default=600, help="seconds to wait for one pass (default 600)"
    )
    ap.add_argument(
        "--max-rounds", type=int, default=int(os.environ.get("MAX_INVESTIGATION_ROUNDS", "3"))
    )
    ap.add_argument(
        "--wait-human", type=int, default=0, help="pause for a real Slack line in phase 9"
    )
    ap.add_argument("--skip-revision", action="store_true", help="stop after the approval gate")
    ap.add_argument(
        "--surface-only", action="store_true", help="phases 1 and 10 only — no LLM spend"
    )
    args = ap.parse_args()

    base = os.environ.get("BASE_URL", "http://localhost:8000").rstrip("/")
    api_key = os.environ.get("API_KEY", "")
    webhook_token = os.environ.get("WEBHOOK_TOKEN", os.environ.get("N8N_WEBHOOK_TOKEN", ""))
    slack_token = os.environ.get("SLACK_BOT_TOKEN", "")
    channel = os.environ.get("SLACK_CHANNEL", "")

    if not api_key:
        print("API_KEY is required", file=sys.stderr)
        return 2

    scenario = SCENARIOS[args.scenario]
    http = Http(base, api_key)
    slack = Slack(slack_token) if slack_token else None
    rep = Report()

    print(f"▸ AgenticIR end-to-end scenario: {args.scenario}")
    print(f"  target   {base}")
    print(f"  incident {scenario['title']}")

    phase_surface(http, rep)
    if args.surface_only:
        phase_ops(http, rep, ran_incident=False)
        return summarise(rep, "", base)

    incident_id = phase_intake(http, rep, scenario, webhook_token)
    if not incident_id:
        phase_ops(http, rep, ran_incident=False)
        return summarise(rep, "", base)

    phase_narration(http, slack, rep, incident_id, channel)
    phase_midflight(http, rep, incident_id, scenario["midflight"])
    record = phase_gate(http, rep, incident_id, args.timeout, args.max_rounds)
    record = phase_approval(http, rep, incident_id, record, args.timeout)
    if not args.skip_revision:
        record = phase_revision(http, rep, incident_id, scenario["revision"], args.timeout)
    phase_views(http, rep, incident_id, record, api_key)
    phase_channel(http, slack, rep, channel, args.wait_human)
    phase_ops(http, rep, ran_incident=True)

    return summarise(rep, incident_id, base)


if __name__ == "__main__":
    sys.exit(main())
