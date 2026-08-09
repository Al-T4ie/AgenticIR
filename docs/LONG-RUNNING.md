# Incidents that last hours

A fifteen-minute incident exercises almost none of this system's interesting
behaviour. It arrives, the graph runs, a report lands, and every mechanism that
matters completes inside one pass. A five-hour incident is a different object:
it spends most of its life *between* runs, and everything that goes wrong with
it goes wrong in the gaps, when nothing is executing and therefore nothing
notices.

This is what the platform does in those gaps, and — equally important — what it
still does not do.

## Where information comes from

There are exactly three sources, and they are not equivalent.

| Source | Direction | Who initiates |
| --- | --- | --- |
| **n8n tools** | pull | the agents, autonomously |
| **The originating alert** | push | once, at intake |
| **Humans in Slack** | push | whoever happens to volunteer it |

The asymmetry is the point. Agents can *fetch* from n8n whenever they decide
they need something. They cannot fetch from a person. `open_questions` publishes
a question into the channel; it does not address it to anyone, set a deadline,
or follow up. The channel poller then reads whatever gets said, if anything
does.

There is **no MCP integration**. If the answer lives in Jira, a CMDB,
PagerDuty, or somebody's head, the only route into the investigation is a human
typing it into Slack.

## What works over five hours

**Late information is folded in, not rejected.** The poller re-reads incident
threads for `SLACK_POLL_THREAD_WINDOW_HOURS` (24 by default), so a note at T+1h
is picked up within one sweep, classified, and applied as a *revision* on the
same graph thread. Prior findings survive — `findings` and `timeline` are
additive — so the re-run builds on what is already known and the revised report
lands in the same place as the original.

**Nothing is read twice.** A cursor per channel plus a claim table
(`slack_seen_messages`, inserted `ON CONFLICT DO NOTHING`) makes each sweep
idempotent across restarts and safe with several workers.

**A crashed run resumes.** `recover_interrupted()` runs once per boot behind a
Postgres advisory lock and restarts anything left mid-flight.

**Information that arrives at a bad moment is queued, not dropped.** A note
landing during a run or under a pending approval goes into `pending_notes` and
is applied when the incident is next idle.

## The caretaker

Three of the gaps above only close if something is awake between runs, which is
what `app/services/upkeep.py` is. It ticks every `UPKEEP_INTERVAL_SECONDS`
independently of the Slack poller, because one of its duties is a correctness
property of the investigation rather than a chat feature.

### A stale plan stops freezing the investigation

Queued notes are only drained when a run *finishes*, and a run parked at an
approval cannot finish until somebody approves. So an unattended gate does not
merely delay containment — it stops the investigation absorbing anything at
all, for as long as the gate stays shut. On a 15-minute incident that is
invisible. On a 5-hour one where the gate opens at minute ten, it is four hours
and fifty minutes of accumulating telemetry and zero analysis.

Past `STALE_GATE_SECONDS` (default 30 min), **with notes actually waiting**, the
plan is withdrawn: the interrupt is resolved with an explicit non-decision,
nothing is executed, and the queue is folded in as the next revision.

Both halves of that condition matter. Time alone is not staleness — a plan
nobody has objected to is still the best plan anyone has. Notes alone are not
either — re-planning on every note would make the gate impossible to ever
approve.

The clock runs from the **oldest un-applied note**, not from the incident's last
activity. `updated_at` moves every time a note is queued, so measuring from it
would reset the timer on exactly the incidents carrying the most new
information.

Nobody is overruled by this. The plan withdrawn is one no human ever ruled on,
and what the approver gets instead is a plan built on everything now known. The
timeline records it as `system`, not as `human:` — attributing the machine's own
housekeeping to a person would corrupt the waiting-on-humans metric and put a
rejection in the record that nobody made. The wait itself still counts against
that metric, because nobody came and that was real.

Set `STALE_GATE_SECONDS=0` to disable and let plans wait indefinitely.

### Catch-ups

In winger and responder modes the bot owes the room a periodic summary. Rather
than a timer per incident, which would not survive a restart, the caretaker asks
the opposite question on each tick — who is overdue — which needs no memory
beyond a column.

A catch-up reports **what changed since the last one**, not what is true in
general, and it does not post when there is nothing to report and nothing is
blocked. Silence means the machine is working and needs nothing. What *is*
blocking is repeated every time, deliberately: an approval nobody has looked at
in two hours is the most useful thing the message can contain, and saying it
once at minute ten is how it stays unlooked-at.

### War rooms are actually read

The poller sweeps `SLACK_POLL_CHANNELS`, fixed at deploy time. That is correct
for the shared incident channel and useless for a room created ten minutes ago —
and an incident gets its own channel precisely so the conversation happens
there. Live rooms are now added to each sweep dynamically, capped per cycle.

Anything said in a room is bound to that room's incident rather than left to the
classifier to guess at, and a new alert posted in a war room joins that incident
instead of opening a second one. Opening a second one would take the room over:
the new incident would claim the channel and every later message in it would be
attributed to the wrong investigation.

## What still does not happen

Two gaps are open by design pending a decision, not by oversight.

**Questions are asked once and never chased.** `asked_before` suppresses
repeats, which is right at fifteen minutes and wrong at five hours. There is no
nudge, no re-ask on a backoff, no @-mention of a named person, no staleness
marking. A question posted at T+5min that nobody answers is still sitting there
at T+5h, and nobody was reminded. The catch-up will list it as outstanding —
that is the only pressure the system currently applies.

**Gaps do not automatically become questions.** Specialists report a `gaps`
field, and it is where the genuinely human-only material lives — *"cannot access
Salesforce Connected App authorization audit logs"*, *"Okta System Log not
provided"*. Whether a gap becomes an `open_question` is entirely the critic's
call, and it promotes a minority of them. Nothing distinguishes "no tool exists
for this" from "a person could answer this in ten seconds".

## Configuration

| Variable | Default | What it does |
| --- | --- | --- |
| `UPKEEP_ENABLED` | `true` | Run the between-runs caretaker at all |
| `UPKEEP_INTERVAL_SECONDS` | `60` | Caretaker tick |
| `STALE_GATE_SECONDS` | `1800` | Age of the oldest queued note before a plan is withdrawn; `0` disables |
| `IR_DIGEST_SECONDS` | `600` | Catch-up cadence in winger and responder modes |
| `SLACK_POLL_THREAD_WINDOW_HOURS` | `24` | How long incident threads and war rooms keep being read |

## Watching it work

```bash
# Caretaker actions, by kind
curl -s https://air.husseinaltaie.com/metrics | grep agenticir_upkeep_actions_total

# Structured logs worth grepping
#   upkeep.started            once at boot, with the thresholds in force
#   upkeep.plan_withdrawn     a gate went stale — incident_id and queued_notes
#   upkeep.swept              any tick that did something
#   poller.rooms_truncated    more live war rooms than one sweep reads
#   poller.investigate_folded_into_room  a room message that would have spawned an incident
```
