# Running an end-to-end incident scenario

This is the pre-release gate. It drives one realistic incident through every
surface a responder touches and grades the deployment on what comes back.

`make smoke` answers *is it up*. This answers *would I hand this to an on-call
analyst tonight* — a different question, and the one where this product's real
failure modes live. A report that contradicts the record it was written from, a
follow-up that returns an error for telemetry it in fact stored, a stage strip
claiming containment already ran on an incident about to run it again: every one
of those passes a health check.

---

## 1. What you need

| Variable | Required | Where it comes from |
|---|---|---|
| `BASE_URL` | yes | `https://air.husseinaltaie.com` for the live deployment |
| `API_KEY` | yes | Coolify → the app → Environment Variables → `API_KEY` |
| `WEBHOOK_TOKEN` | no | `N8N_WEBHOOK_TOKEN`. Without it, intake falls back to the authenticated API and the SIEM path is reported unverified |
| `SLACK_BOT_TOKEN` | no | `xoxb-…`. Without it the Slack phases become warnings |
| `SLACK_CHANNEL` | no | The channel **ID** (`C0…`), not the name |

Nothing but `BASE_URL` and `API_KEY` is mandatory. Each missing credential
downgrades its phase to a warning rather than failing the run, so the same
harness works against a bare `make up` stack.

## 2. Run it

```bash
export BASE_URL=https://air.husseinaltaie.com
export API_KEY='…'
export WEBHOOK_TOKEN='…'
export SLACK_BOT_TOKEN='xoxb-…'
export SLACK_CHANNEL='C0BNHCPQJPR'

make e2e
```

Roughly **10–20 minutes** and **a few cents** of model spend — it runs two full
passes of the graph plus a revision.

Useful variants:

```bash
make e2e-surface                                  # contract + ops only, no LLM spend, ~5s
make e2e ARGS='--scenario phishing-false-positive'  # exercise the benign path
make e2e ARGS='--skip-revision'                     # stop after the approval gate
make e2e ARGS='--wait-human 300'                    # pause so you can type in Slack
```

Exit code is **0 unless a blocker fired**, so it drops straight into CI.

## 3. What it walks through

| Phase | The question it answers |
|---|---|
| 1. Surface | Does an unauthenticated caller get the contract we promised — 401s where they belong, `/ui` bouncing to login, an empty body 422ing rather than starting a run |
| 2. Intake | A SIEM posts an alert nobody is watching for. Is it accepted and given an id |
| 3. Narration | Did a Slack thread open **before** the run finished, and is progress edited in place rather than re-posted 17 times |
| 4. Mid-flight | A second source arrives while the graph is running. Is it accepted and queued, and does the response say which |
| 5. Investigation | Does it reach a decision, produce findings, respect the round cap, and stay concise enough to read |
| 6. Human gate | Are the proposed actions enumerated, does approval resume the run, and does the queued telemetry get folded in |
| 7. Revision | New information about an already-closed incident. Does it reopen, re-assess and change the record |
| 8. Views | The incident page and the report page — graph drawn, timeline drawn, ATT&CK resolved, headline matching the stored verdict, no CDN references, no raw markdown |
| 9. Channel | Does an out-of-band sweep run. With `--wait-human`, does a real line in the channel get picked up |
| 10. Ops | Metrics exposed, this run counted, poller sweeping, no LLM failures accumulating |

## 4. Reading the result

```
  ✓  passed
  !  warning  — works, but degraded or could not be proven from outside
  ✗  BLOCKER  — not fit to ship
```

The distinction matters. "Slack narration not verified because no token was
supplied" and "Slack narration is broken" produce very different marks, and
collapsing them into one is how a green run stops meaning anything.

The summary prints the incident id and direct links to its timeline and report,
so a failure is one click from the evidence.

### Warnings you should expect

- **`runs since boot 0`** on a freshly deployed container. Prometheus counters
  are per-process and reset on deploy. Only meaningful once the harness has
  actually driven a run through, which is why the check is conditional.
- **`nothing needed approving on this run`** if the model proposes no
  containment. Legitimate on the false-positive scenario, worth a look on the
  ransomware one.
- **`a human line in the channel`** is skipped by default. The bot token can
  only post *as the bot*, and the poller deliberately ignores bot messages so it
  cannot loop on its own output — so that leg needs a person. Run with
  `--wait-human 300` and type something in the channel.

## 5. Adding a scenario

`SCENARIOS` at the top of `infra/scripts/e2e_scenario.py`. Each one is an alert
plus two follow-ups — one that lands mid-run, one that lands after close.

Keep that shape. The first pass is not the interesting part; what happens when a
second source arrives while the graph is mid-flight, and what happens when it
arrives after the report is already published, is where the product is either
right or wrong.
