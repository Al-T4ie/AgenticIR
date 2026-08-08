# Getting AgenticIR live and demoing it

Target setup: **your existing Coolify**, **Anthropic** models, **simulated
containment**, **your own domain**. Roughly 60–75 minutes of wall clock, most of
it the first container build and Slack app setup.

---

## 1. What I need from you

Nothing here is optional except where marked. Values marked **secret** should go
straight into Coolify's environment editor, not into chat or the repo.

### Required to deploy

| Value | Where it comes from | Notes |
|---|---|---|
| `COOLIFY_URL` | Your Coolify dashboard URL | e.g. `https://coolify.yourdomain.com` |
| `COOLIFY_API_TOKEN` **secret** | Coolify → Keys & Tokens → API tokens → create, **read/write** | Must be read/write; a read token 403s on resource creation |
| Which Coolify **server** to deploy to | Coolify → Servers | Only needed if you have more than one; otherwise I take the first |
| Your **domain** | You said you have one | I need the two hostnames you want — see below |
| An LLM key **secret** | Anthropic direct, or OpenRouter | See "LLM provider" below. Demo run costs a few cents |
| Git repo URL | Where this code will live | Coolify builds **from git**, so the branch has to be pushed and reachable by Coolify. See §2. |

### LLM provider

Two supported routes to Claude models:

**Direct Anthropic** — `LLM_PROVIDER=anthropic`, `ANTHROPIC_API_KEY=sk-ant-…`.
Model IDs are bare (`claude-sonnet-5`). This is the default and the best-tested
path.

**OpenRouter** — `LLM_PROVIDER=openrouter`, `OPENROUTER_API_KEY=sk-or-v1-…`
(`OPENROUTER_API_TOKEN` is accepted as an alias). Two things change:

1. **Model IDs are namespaced.** `claude-sonnet-5` is not a valid OpenRouter
   model. All three must be set explicitly, or every call fails with
   model-not-found. The configured set:

   | Role | Model | Cost /M in-out | Context |
   |---|---|---|---|
   | supervisor | `minimax/minimax-m3` | $0.30 / $1.20 | 1.0M |
   | specialist | `anthropic/claude-haiku-4.5` | $1.00 / $5.00 | 200k |
   | critic | `openai/gpt-5.6-terra` | $1.00 / $6.00 | 1.05M |

   All three advertise `tools`, `tool_choice` and `structured_outputs`, which
   every role depends on — the supervisor and critic emit structured objects
   and the specialists run a tool loop.

   This is deliberately cross-vendor. The critic's job is to attack the
   specialists' conclusions, and it does that more honestly coming from a
   different lab than the models it reviews.

   Verify IDs against <https://openrouter.ai/models> if you change them; a
   model without tool support will fail on its first structured call.

2. **Structured output uses tool calling**, forced automatically. OpenRouter
   does not reliably implement OpenAI's native `json_schema` strict mode, and
   an unsupported request surfaces as an opaque 400 rather than degrading.
   Pick models that support tool calling — all Anthropic models on OpenRouter
   do.

Any other OpenAI-compatible gateway (LiteLLM, vLLM, a corporate proxy) works
via `LLM_PROVIDER=openai` plus `OPENAI_BASE_URL`.

### Hostnames

Pick two subdomains and create A records pointing at your Coolify server's IP
**before** deploying — Let's Encrypt validates over HTTP, so TLS issuance fails
if they don't resolve yet.

```
ir.yourdomain.com        →  <coolify server IP>     # API, dashboard, Slack endpoints
ir-n8n.yourdomain.com    →  <coolify server IP>     # only if using the bundled n8n
```

Tell me the two names and I'll set `APP_FQDN` / `N8N_FQDN`.

### Required for the Slack demo

| Value | Where |
|---|---|
| `SLACK_BOT_TOKEN` **secret** | Created in step 4 — `xoxb-…` from OAuth & Permissions |
| `SLACK_SIGNING_SECRET` **secret** | Same app → Basic Information |
| Channel name | e.g. `#incident-response` — create it and invite the bot |

You need permission to install an app in that Slack workspace. If you don't have
it, someone with it must click through step 4; everything else still works.

### One decision I still need

**Your n8n, or the bundled one?**

- **Bundled** (default): the stack ships its own n8n in queue mode. Self-contained,
  won't disturb your existing automations, needs the `ir-n8n` hostname. Use
  `docker-compose.coolify.yml`.
- **Yours**: use `docker-compose.coolify-external-n8n.yml`. I need
  `N8N_BASE_URL` (must be reachable *from the container* — a public HTTPS URL
  always works) and you pick an `N8N_WEBHOOK_TOKEN` that I set on both sides.
  No second hostname needed.

For a demo I'd use the bundled one — it isolates the blast radius and the tool
wiring works out of the box.

### Not needed

No SIEM, no EDR, no threat-intel subscription, no Hetzner token (you're on
existing Coolify). Containment is simulated and intel comes from fixtures.

---

## 2. The one real blocker

**Coolify deploys from a git repository, so this code has to be pushed
somewhere Coolify can clone.**

I could not push it — GitHub returns `403` on both `git push` and the GitHub API
(`Resource not accessible by integration`); the session's GitHub integration is
read-only on `Al-T4ie/AgenticIR`. Reads work fine, so this is a write-permission
grant, not a network problem.

Pick one:

1. **Grant write access** to the Claude GitHub integration and I'll push
   `claude/self-hosted-ir-platform-bayf68` directly.
2. **Apply the bundle I sent you** — restores the branch byte-identically:
   ```bash
   git clone https://github.com/Al-T4ie/AgenticIR && cd AgenticIR
   git fetch /path/to/agenticir-ir-platform.bundle 'refs/heads/*:refs/heads/*'
   git checkout claude/self-hosted-ir-platform-bayf68
   git push -u origin claude/self-hosted-ir-platform-bayf68
   ```

If the repo is **private**, Coolify also needs read access to it — add a deploy
key or connect the GitHub app in Coolify → Sources.

---

## 3. Deploy

```bash
export COOLIFY_URL='https://coolify.yourdomain.com'
export COOLIFY_API_TOKEN='...'
export GIT_REPOSITORY='https://github.com/Al-T4ie/AgenticIR'
export GIT_BRANCH='claude/self-hosted-ir-platform-bayf68'

export APP_FQDN='ir.yourdomain.com'
export N8N_FQDN='ir-n8n.yourdomain.com'      # omit if using your own n8n

export ANTHROPIC_API_KEY='sk-ant-...'
export N8N_ENABLED=true

python3 infra/coolify/bootstrap.py
```

It creates the project, creates the compose resource, syncs environment
variables, deploys, and waits for `/health`. Idempotent — re-run freely.

For your own n8n, add:

```bash
export N8N_BASE_URL='https://n8n.yourdomain.com'
export N8N_WEBHOOK_TOKEN="$(openssl rand -hex 32)"   # keep this, you need it in n8n
python3 infra/coolify/bootstrap.py \
  --compose-path docker-compose.coolify-external-n8n.yml
```

**Grab the generated API key** from Coolify → resource → Environment Variables →
`API_KEY`. That is the dashboard login and the `X-API-Key` header.

Verify:

```bash
BASE_URL=https://ir.yourdomain.com API_KEY='<from Coolify>' \
  bash infra/scripts/smoke-test.sh
```

---

## 4. Slack

1. api.slack.com/apps → **Create New App → From an app manifest**
2. Paste `infra/slack/manifest.yaml`, replacing `app.example.com` with your
   `APP_FQDN` in all three URLs
3. Install to workspace
4. In Coolify set `SLACK_ENABLED=true`, `SLACK_BOT_TOKEN`,
   `SLACK_SIGNING_SECRET`, `SLACK_DEFAULT_CHANNEL`, then redeploy
5. `/invite @IR Bot` in the channel

Slack verifies the Events URL when you save the manifest, so the app must
already be deployed and serving HTTPS. If it fails, check that
`POST /slack/events` returns **401** (not 502) for an unsigned request — 401
means the app is up and rejecting correctly.

---

## 5. n8n workflows

Open n8n → **Workflows → Import from file**, once per file in
`infra/n8n/workflows/`:

| File | Purpose |
|---|---|
| `01-siem-alert-intake.json` | Inbound: SIEM webhook → filter → start investigation |
| `02-agent-tool-enrich-ioc.json` | Outbound tool: threat-intel lookup |
| `03-agent-tool-contain-host.json` | Outbound tool: **simulated** host isolation + Slack confirmation |

On each **agent-callable** webhook node (02 and 03), add a **Header Auth**
credential:

```
Name:  Authorization
Value: Bearer <N8N_WEBHOOK_TOKEN>
```

Bundled n8n: that token is `SERVICE_BASE64_64_N8NTOKEN` in Coolify's env tab.
Your own n8n: it's the value you generated in step 3.

Set these in the n8n environment (bundled: add to the Coolify resource; yours:
however you manage n8n env):

```
AGENTICIR_DEMO_INTEL=true         # serves labelled demo fixtures
SLACK_BOT_TOKEN=xoxb-...          # so workflow 03 can post its confirmation
SLACK_DEFAULT_CHANNEL=#incident-response
```

**Activate all three workflows** (toggle top-right) — inactive workflows return
404 to the agents.

Finally, register the tools with the agents in Coolify and redeploy:

```
N8N_TOOLS=enrich_ioc:agentic-ir/enrich-ioc:Look up an IP/domain/hash in threat intel,contain_host:agentic-ir/contain-host:Isolate a host from the network
```

---

## 6. The demo

```bash
BASE_URL=https://ir.yourdomain.com API_KEY='...' bash infra/scripts/demo-seed.sh
```

Three scenarios, each taking a different path. **The point is that they end
differently** — a system that escalates everything is just an expensive pager.

### Scenario 1 — true positive → containment → human gate

Encoded PowerShell spawned by Outlook, beaconing to a domain registered 11 days
ago. Watch: supervisor dispatches three specialists **at once**; enrichment
calls your n8n workflow and gets the C2 verdict back; behavioral maps it to
ATT&CK; critic confirms **true positive / critical**; containment proposes
`isolate_host`, marked high-risk, so the graph **stops** and posts approval
buttons to Slack.

Click **Approve all**. Workflow 03 fires, posts its `[SIMULATED]` confirmation,
and the incident closes with the approver recorded on the timeline.

**Say this out loud during the demo:** the model proposed that action, but
whether it needed a human was decided by `containment.py`, not by the model. It
cannot talk its way past the gate.

### Scenario 2 — false positive → closes on its own

A 48 MB upload to a supplier domain, during working hours, ninth time this
quarter, all previously closed benign. The critic reaches **false positive** and
the containment planner proposes **nothing**. No approval, no page.

This is the one that earns trust. Show it second.

### Scenario 3 — inconclusive → escalates instead of guessing

A privileged service account with no MFA, 47 failed sign-ins then a success from
an external IP — but overlapping an approved change window whose ticket contents
the pipeline can't see. The intel fixture deliberately has two providers
**disagreeing** about the source IP.

The right answer is *"I can't tell you, here's exactly what a human must check."*
Watch the report name the specific gap: nobody read CHG-8841, nobody called the
on-call engineer.

### Also worth showing

- **Slack-native start**: `@IR Bot investigate <paste an alert>` — findings come
  back in-thread.
- **Follow-up in thread**: reply `@IR Bot what was the C2 domain again?` — it
  answers from the incident record, not a fresh investigation.
- **Durability** (the strongest technical beat): while scenario 1 sits at the
  approval gate, restart the API in Coolify. Then approve. It resumes from the
  checkpoint. Nothing is held in memory.
- **The dashboard**: `/ui` — findings with evidence, ATT&CK mapping, timeline.
- **Cost**: `/metrics`, or LangSmith if you set `LANGSMITH_TRACING=true`.

---

## 7. Honest caveats

Say these before someone else finds them:

- **Containment is simulated.** Workflow 03 modifies nothing; every response is
  tagged `simulated: true` and every Slack confirmation says `[SIMULATED]`.
- **Threat intel is fixtures.** Real feeds are one node swap away, but today the
  verdicts are canned and tagged `demo_fixture: true`. Unknown indicators return
  `unknown`, never "clean" — a fabricated clean verdict is how you suppress a
  real detection.
- **This is not a detection engine.** It reasons about alerts something else
  produced. It will not find what your SIEM missed.
- **Non-determinism.** Two runs of the same alert can word things differently
  and occasionally land on a different severity. The verdict/severity/approval
  *policy* is deterministic; the prose is not. If you need a fixed demo, run it
  once beforehand and show the stored incident.
- **Never demoed against production.** Everything here has run against fixtures.
  Do a dry run on simulated actions before pointing containment at a real EDR.

---

## 8. Going live afterwards

1. Replace the simulate node in workflow 03 with your EDR's API call. Keep the
   response shape.
2. Point workflow 02 at real feeds. Keep the unknown-≠-benign rule.
3. Set your SIEM to POST alerts at
   `https://ir-n8n.yourdomain.com/webhook/agentic-ir/alert`, or straight to
   `https://ir.yourdomain.com/webhooks/alert` with a bearer token.
4. Tune `AUTO_APPROVE_SEVERITY_BELOW`. Start at `never` — everything needs a
   human — and relax it only once you trust the verdicts.
5. Turn on `LANGSMITH_TRACING` before you scale volume, not after.
