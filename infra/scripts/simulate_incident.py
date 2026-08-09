#!/usr/bin/env python3
"""Run one incident at human speed and narrate everything the platform does.

`e2e_scenario.py` answers "does it work" as fast as possible. This answers a
different question — "what does it actually look like while it's working" — and
that needs the opposite of speed. Real telemetry does not arrive in one payload;
it trickles in over the first quarter hour while the responder is still reading
the first alert, and the interesting behaviour is what the graph does with a
fact that shows up after it has already formed a view.

So: ten minutes of injections on a schedule, then five minutes of settling while
the agents reconcile what arrived, then an executive readout built from the
record rather than from the model's prose.

While it runs it prints, live:

  · every timeline event as it lands, tagged by what produced it
  · which specialists the supervisor dispatched, and which came back
  · each critic round and whether it asked for another
  · n8n webhook calls, counted off the tool-call metric
  · the approval gate, and what was proposed
  · every open question the moment it is raised

and at the end, which of those questions the later telemetry answered.

    BASE_URL=… API_KEY=… WEBHOOK_TOKEN=… python3 infra/scripts/simulate_incident.py

There is no MCP in this platform — it neither exposes nor consumes a server —
so there is nothing to watch on that front. The external tool surface is n8n,
and that is what the tool-call counters cover.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
from typing import Any

# ── The injections ───────────────────────────────────────────────────────────
# Offsets are seconds from the start. The first is the alert itself; the rest
# arrive as follow-ups the way a SOC actually learns things — the identity team
# checks their logs, the service desk finds related calls, legal gets an email.
#
# Several will land while the graph is mid-pass and be queued rather than
# applied, which is the point: that path only shows up when injections are
# spaced against a run that takes about ninety seconds.

PLAN: list[dict[str, Any]] = [
    {
        "at": 0,
        "kind": "alert",
        "from": "Salesforce Shield",
        "label": "the alert",
        "file": "examples/demo-04-shinyhunters-saas.json",
    },
    {
        "at": 120,
        "kind": "note",
        "from": "identity-team",
        "label": "Okta: the MFA push that was approved on the second try",
        "note": (
            "Okta: r.delacruz approved a push at 12:57:44 UTC from 185.65.135.42, "
            "13 seconds after declining one from the same IP. Her device has never "
            "authenticated from that ASN before. Session was not stepped up."
        ),
    },
    {
        "at": 270,
        "kind": "note",
        "from": "service-desk",
        "label": "helpdesk: the pretext calls nobody connected",
        "note": (
            "Service desk logged three calls that morning from a caller with an "
            "Australian accent asking which staff hold Salesforce admin, claiming to "
            "be from 'the Salesforce trust team' doing a licence audit. Two agents "
            "answered the question. None of the calls were ticketed as security."
        ),
    },
    {
        "at": 420,
        "kind": "note",
        "from": "casb",
        "label": "CASB: a second tenant, same tradecraft",
        "note": (
            "Netskope: a connected app with the same publisher fingerprint was "
            "authorised against our Zendesk tenant at 13:44 UTC by a different user "
            "in Customer Success, from 185.65.135.51 — adjacent IP, same ASN. That "
            "app has not exported yet. Zendesk holds customer support transcripts."
        ),
    },
    {
        "at": 570,
        "kind": "note",
        "from": "legal",
        "label": "the extortion email",
        "note": (
            "Extortion email received at legal@example.com from a ProtonMail address. "
            "It quotes the exact export count (1,204,719), includes 20 verifiably real "
            "Account records, names the group, and gives 72 hours before publication "
            "on a leak site. Salesforce confirms the connected app's refresh token is "
            "still valid and was used again 20 minutes ago."
        ),
    },
]

TRICKLE_ENDS = 600  # 10 minutes of arrivals
TOTAL = 900  # then five minutes to settle

# ── Terminal ─────────────────────────────────────────────────────────────────
C = {
    "dim": "\033[2m",
    "b": "\033[1m",
    "r": "\033[0m",
    "cyan": "\033[36m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "red": "\033[31m",
    "blue": "\033[34m",
    "mag": "\033[35m",
}
if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
    C = dict.fromkeys(C, "")

# actor -> (colour, what it is). Anything unlisted prints plain.
ACTOR_STYLE = {
    "intake": ("cyan", "graph"),
    "supervisor": ("mag", "graph"),
    "triage": ("green", "specialist"),
    "enrichment": ("green", "specialist"),
    "behavioral": ("green", "specialist"),
    "critic": ("yellow", "graph"),
    "containment_planner": ("blue", "graph"),
    "executor": ("blue", "graph"),
    "reporter": ("cyan", "graph"),
}


def paint(text: str, colour: str) -> str:
    return f"{C.get(colour, '')}{text}{C['r']}"


# ── HTTP ─────────────────────────────────────────────────────────────────────
class Http:
    def __init__(self, base: str, api_key: str, hook: str) -> None:
        self.base, self.api_key, self.hook = base.rstrip("/"), api_key, hook
        self.ctx = ssl.create_default_context()

    def call(
        self, path: str, *, method: str = "GET", payload: Any = None, bearer: str = ""
    ) -> tuple[int, Any]:
        headers = {"Content-Type": "application/json"}
        if bearer:
            headers["Authorization"] = f"Bearer {bearer}"
        else:
            headers["X-API-Key"] = self.api_key
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=60, context=self.ctx) as r:
                body = r.read().decode("utf-8", "replace")
                status = r.status
        except urllib.error.HTTPError as exc:
            status, body = exc.code, exc.read().decode("utf-8", "replace")
        except Exception as exc:  # noqa: BLE001
            return 0, str(exc)
        try:
            return status, json.loads(body)
        except Exception:  # noqa: BLE001
            return status, body

    def metrics(self) -> str:
        req = urllib.request.Request(self.base + "/metrics")
        try:
            with urllib.request.urlopen(req, timeout=30, context=self.ctx) as r:
                return r.read().decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            return ""


def tool_calls(metrics: str) -> dict[str, float]:
    """Per-tool invocation counts. These are the n8n webhooks, when n8n is on."""
    out: dict[str, float] = {}
    for m in re.finditer(
        r'^agenticir_tool_calls_total\{[^}]*tool="([^"]+)"[^}]*outcome="([^"]+)"[^}]*\} ([0-9.e+-]+)$',
        metrics,
        re.M,
    ):
        out[f"{m.group(1)}/{m.group(2)}"] = float(m.group(3))
    return out


# ── Live narration ───────────────────────────────────────────────────────────
class Narrator:
    """Prints each new timeline entry once, and keeps a running tally."""

    def __init__(self, started: float) -> None:
        self.started = started
        self.seen = 0
        self.rounds = 0
        self.dispatched: list[str] = []
        self.reported: set[str] = set()
        self.questions: list[tuple[str, str]] = []  # (clock, question)
        self.gaps: list[tuple[str, str]] = []  # (specialist, gap text)
        self.revisions = 0
        self.next_node = ""

    def clock(self) -> str:
        secs = int(time.time() - self.started)
        return f"{secs // 60:02d}:{secs % 60:02d}"

    def line(self, tag: str, colour: str, text: str) -> None:
        print(
            f"  {C['dim']}{self.clock()}{C['r']}  {paint(f'{tag:<12}', colour)} {text}", flush=True
        )

    def event(self, entry: dict[str, Any]) -> None:
        actor = str(entry.get("actor", ""))
        text = str(entry.get("event", ""))
        colour, kind = ACTOR_STYLE.get(actor, ("", ""))

        if actor.startswith("human:") or actor == "channel":
            self.line("human", "b", text[:150])
            if "Revision" in text:
                self.revisions += 1
            return

        if actor == "supervisor" and "dispatched" in text:
            self.rounds += 1
            names = text.split("dispatched", 1)[1].strip().rstrip(".")
            self.dispatched = [n.strip() for n in names.split(",")]
            self.line("supervisor", colour, f"round {self.rounds} — fans out to {names}")
            for n in self.dispatched:
                self.line("  ├─ Send", "dim", f"{n} agent spawned")
            return

        if kind == "specialist":
            self.reported.add(actor)
            head, _, gap = text.partition("gaps:")
            self.line(actor, colour, head.strip().rstrip(";"))
            if gap.strip():
                self.gaps.append((actor, gap.strip()))
                self.line("  └─ gap", "dim", gap.strip()[:120])
            return

        if actor == "critic":
            more = "requesting another round" in text
            self.line("critic", colour, text.replace("Review: ", ""))
            if not more:
                self.line("  └─ loop", "dim", "no further rounds — moving to containment")
            return

        self.line(actor or "event", colour, text[:150])

    def new_questions(self, questions: list[str]) -> None:
        known = {q for _, q in self.questions}
        for q in questions:
            if q not in known:
                self.questions.append((self.clock(), q))
                self.line("question", "yellow", q[:140])


# ── Main ─────────────────────────────────────────────────────────────────────
def summarise(
    http: Http, incident_id: str, nar: Narrator, base: str, tools0: dict[str, float]
) -> None:
    _, rec = http.call(f"/v1/incidents/{incident_id}")
    if not isinstance(rec, dict):
        print("could not read the incident for the summary")
        return

    def hr(title: str) -> None:
        print(f"\n{C['b']}{title}{C['r']}\n{'─' * 74}")

    hr("EXECUTIVE READOUT")
    print(f"  incident    {rec['id']}")
    print(f"  title       {rec['title']}")
    conf = rec.get("confidence")
    print(
        f"  verdict     {paint(str(rec.get('verdict')), 'b')}   severity {rec.get('severity')}"
        f"   confidence {f'{conf:.0%}' if isinstance(conf, (int, float)) else '—'}"
    )
    print(f"  status      {rec.get('status')}")
    print(f"  findings    {len(rec.get('findings') or [])}  across {nar.revisions + 1} pass(es)")

    if rec.get("report"):
        hr("THE PUBLISHED REPORT")
        for para in str(rec["report"]).split("\n"):
            print(f"  {para}")

    # ATT&CK, resolved locally the same way the dashboard does it.
    hr("ATT&CK CHAIN")
    cited: set[str] = set()
    for f in rec.get("findings") or []:
        for t in f.get("mitre_techniques") or []:
            cited.add(str(t).strip())
    try:
        sys.path.insert(0, os.getcwd())
        from app.services import attack  # noqa: PLC0415

        lanes: dict[str, list[str]] = {}
        unmapped = []
        for tid in sorted(cited):
            name, tactics, _ = attack.describe(tid)
            if not name:
                unmapped.append(tid)
                continue
            for tac in tactics:
                lanes.setdefault(tac, []).append(f"{tid} {name}")
        for key, label in attack.TACTICS:
            if key in lanes:
                print(f"  {label:<18} {', '.join(sorted(set(lanes[key])))}")
        if unmapped:
            print(f"  {paint('unmapped', 'red'):<18} {', '.join(unmapped)}")
    except Exception:  # noqa: BLE001 — run from anywhere; fall back to a flat list
        print(f"  cited: {', '.join(sorted(cited)) or 'none'}")

    hr("CONTAINMENT")
    for a in rec.get("containment_actions") or []:
        risk = str(a.get("risk", "?"))
        flag = paint(risk, "red" if risk == "high" else "dim")
        rev = "reversible" if a.get("reversible") else paint("IRREVERSIBLE", "red")
        print(f"  · {a.get('action'):<16} {str(a.get('target'))[:52]:<52} {flag}/{rev}")
    executed = rec.get("executed_actions") or []
    print(f"  executed: {len(executed)}")

    hr("QUESTIONS IT RAISED, AND WHERE THEY LANDED")
    still_open = {q.strip() for q in (rec.get("open_questions") or [])}
    if not nar.questions:
        print("  none raised")
    for clock, q in nar.questions:
        resolved = q.strip() not in still_open
        mark = paint("answered", "green") if resolved else paint("still open", "yellow")
        print(f"  [{clock}] {mark}")
        print(f"          {q}")

    hr("GOTCHAS")
    gotchas: list[str] = []
    for a in rec.get("containment_actions") or []:
        if a.get("risk") == "high":
            gotchas.append(
                f"high-risk action proposed: {a.get('action')} → {str(a.get('target'))[:60]}"
            )
        if not a.get("reversible"):
            gotchas.append(f"irreversible action proposed: {a.get('action')}")
    if rec.get("pending_notes"):
        gotchas.append(f"{len(rec['pending_notes'])} note(s) still queued and never applied")
    if rec.get("errors"):
        gotchas.append(f"{len(rec['errors'])} error(s) recorded during the run")
    weak = [f for f in rec.get("findings") or [] if (f.get("confidence") or 1) < 0.5]
    if weak and str(rec.get("severity")) in {"high", "critical"}:
        gotchas.append(
            f"{len(weak)} low-confidence finding(s) underpinning a {rec.get('severity')} verdict"
        )
    if still_open:
        gotchas.append(f"{len(still_open)} question(s) the agents could not close without a human")
    for g in gotchas or ["none"]:
        print(f"  ! {g}")

    hr("FYI — WHAT NOBODY COULD FIND OUT")
    if not nar.gaps:
        print("  no gaps recorded")
    for specialist, gap in nar.gaps[-8:]:
        print(f"  · {specialist:<12} {gap[:110]}")

    hr("TOOLS AND EXTERNAL CALLS")
    tools1 = tool_calls(http.metrics())
    delta = {k: tools1.get(k, 0) - tools0.get(k, 0) for k in set(tools1) | set(tools0)}
    fired = {k: v for k, v in delta.items() if v}
    if fired:
        for k, v in sorted(fired.items()):
            print(f"  · {k:<32} {v:+.0f}   (n8n webhook when the tool is n8n-backed)")
    else:
        print("  no tool invocations recorded during this window")
    print(
        f"  {C['dim']}MCP: none — this platform neither exposes nor consumes an MCP server{C['r']}"
    )

    hr("LOOK AT IT")
    print(f"  agent graph + timeline   {base}/ui/incidents/{incident_id}")
    print(f"  the report               {base}/ui/incidents/{incident_id}/report")
    print(
        f"  Slack thread             channel {os.environ.get('SLACK_CHANNEL', '(configured default)')}"
    )
    print("─" * 74)


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--total", type=int, default=TOTAL, help="seconds to run (default 900)")
    ap.add_argument(
        "--approve-after",
        type=int,
        default=45,
        help="seconds to leave an approval gate visible before approving (0 = never)",
    )
    ap.add_argument(
        "--speed", type=float, default=1.0, help="compress the schedule, e.g. 4 = 4x faster"
    )
    args = ap.parse_args()

    base = os.environ.get("BASE_URL", "http://localhost:8000").rstrip("/")
    api_key = os.environ.get("API_KEY", "")
    hook = os.environ.get("WEBHOOK_TOKEN", os.environ.get("N8N_WEBHOOK_TOKEN", ""))
    if not api_key:
        print("API_KEY is required", file=sys.stderr)
        return 2

    http = Http(base, api_key, hook)
    tools0 = tool_calls(http.metrics())
    started = time.time()
    nar = Narrator(started)
    scale = 1.0 / max(args.speed, 0.01)

    print(f"{C['b']}▸ Staged incident simulation{C['r']}")
    print(f"  target        {base}")
    print(f"  trickle       {len(PLAN)} injections over {int(TRICKLE_ENDS * scale / 60)} min")
    print(f"  then          settle until {int(args.total * scale / 60)} min")
    print(f"  approval      auto after {args.approve_after}s at the gate\n")

    incident_id = ""
    pending: list[dict[str, Any]] = list(PLAN)
    gate_since = 0.0
    last_status = ""

    while True:
        now = time.time() - started
        if now > args.total * scale:
            break

        # ── inject anything due ──────────────────────────────────────────
        while pending and now >= pending[0]["at"] * scale:
            beat = pending.pop(0)
            if beat["kind"] == "alert":
                path = beat["file"]
                if not os.path.exists(path):
                    print(f"missing {path} — run from the repo root", file=sys.stderr)
                    return 2
                with open(path) as fh:
                    alert = json.load(fh)
                status, body = (
                    http.call(
                        "/webhooks/alert",
                        method="POST",
                        bearer=hook,
                        payload={"source": "salesforce-shield", "alert": alert},
                    )
                    if hook
                    else http.call(
                        "/v1/incidents", method="POST", payload={"source": "sim", "alert": alert}
                    )
                )
                incident_id = (
                    str((body or {}).get("incident_id", "")) if isinstance(body, dict) else ""
                )
                nar.line(
                    "INJECT", "b", f"{beat['from']} — {beat['label']}  → {incident_id or body}"
                )
                if not incident_id:
                    return 1
            else:
                status, body = http.call(
                    f"/v1/incidents/{incident_id}/follow-up",
                    method="POST",
                    payload={"note": beat["note"], "reported_by": beat["from"]},
                )
                outcome = (body or {}).get("status", "?") if isinstance(body, dict) else body
                verb = (
                    "applied now"
                    if outcome == "revising"
                    else f"{outcome} — waits for the graph to go idle"
                )
                nar.line("INJECT", "b", f"{beat['from']} — {beat['label']}  [{verb}]")

        if not incident_id:
            time.sleep(2)
            continue

        # ── read state, narrate anything new ─────────────────────────────
        _, rec = http.call(f"/v1/incidents/{incident_id}")
        if not isinstance(rec, dict):
            time.sleep(5)
            continue

        # The incident row is only written when the graph reaches a stopping
        # point, so polling it shows nothing for the ninety seconds a pass takes
        # and then everything at once. The checkpointer is written per superstep,
        # which is what makes node-by-node narration possible at all.
        _, snap = http.call(f"/v1/incidents/{incident_id}/state")
        values = snap.get("values") if isinstance(snap, dict) else None
        live = values if isinstance(values, dict) else rec

        timeline = live.get("timeline") or rec.get("timeline") or []
        for entry in timeline[nar.seen :]:
            nar.event(entry)
        nar.seen = len(timeline)
        nar.new_questions(live.get("open_questions") or [])

        # `next` names the node LangGraph would run now — the one thing the
        # timeline cannot tell you, because it has not happened yet.
        nxt = ", ".join(snap.get("next") or []) if isinstance(snap, dict) else ""
        if nxt and nxt != nar.next_node:
            nar.next_node = nxt
            nar.line("→ next", "dim", f"graph will run: {nxt}")

        status = str(rec.get("status", ""))
        if status != last_status:
            depth = len(rec.get("pending_notes") or [])
            extra = f"  ({depth} note(s) queued)" if depth else ""
            nar.line("status", "dim", f"{last_status or '—'} → {status}{extra}")
            last_status = status
            gate_since = time.time() if status == "awaiting_approval" else 0.0

        # ── the gate ─────────────────────────────────────────────────────
        if status == "awaiting_approval" and args.approve_after and gate_since:
            waited = time.time() - gate_since
            if waited >= args.approve_after:
                acts = [
                    a for a in rec.get("containment_actions") or [] if a.get("requires_approval")
                ]
                nar.line(
                    "APPROVE",
                    "b",
                    f"releasing {len(acts)} action(s) after {waited:.0f}s at the gate",
                )
                http.call(
                    f"/v1/incidents/{incident_id}/approve",
                    method="POST",
                    payload={
                        "approved_all": True,
                        "approved_actions": [a["action"] for a in acts],
                        "approver": "simulation",
                        "note": "approved by the staged simulation",
                    },
                )
                gate_since = 0.0

        time.sleep(5)

    nar.line("END", "b", "trickle and settle window complete")
    summarise(http, incident_id, nar, base, tools0)
    return 0


if __name__ == "__main__":
    sys.exit(main())
