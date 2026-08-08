# Operations runbook

Running the platform itself. For deploying it the first time, see
[DEPLOYMENT.md](DEPLOYMENT.md).

---

## Daily health

```bash
curl -s https://$APP_FQDN/health          # liveness
curl -s https://$APP_FQDN/ready           # readiness — also checks the database
curl -s https://$APP_FQDN/metrics | grep agenticir_
```

Metrics worth alerting on:

| Metric | Watch for |
|---|---|
| `agenticir_runs_completed_total{status="failed"}` | Rising — LLM outage or bad config |
| `agenticir_llm_calls_total{outcome="error"}` | Provider throttling |
| `agenticir_tool_calls_total{outcome="error"}` | An n8n workflow is broken |
| `agenticir_node_duration_seconds` | p95 climbing — model latency or tool timeouts |
| `agenticir_runs_started_total` | Flat when it shouldn't be — intake path broken |

Incidents stuck in `awaiting_approval` are working as designed; they wait
indefinitely. Find them:

```bash
curl -s -H "X-API-Key: $API_KEY" \
  "https://$APP_FQDN/v1/incidents?status=awaiting_approval" | jq '.incidents[].id'
```

---

## Backups

cloud-init installs `agenticir-backup.timer`, running nightly at 03:15 UTC:
`pg_dumpall` of every Postgres container plus a tarball of `/data/coolify`,
written to `/data/backups` with 14-day retention.

```bash
ssh root@$SERVER_IP systemctl list-timers agenticir-backup.timer
ssh root@$SERVER_IP ls -lh /data/backups
ssh root@$SERVER_IP systemctl start agenticir-backup.service   # run one now
```

**These live on the same volume as the data they protect.** That covers "someone
dropped a table", not "the volume is gone". For real durability add at least one:

- Hetzner volume snapshots (console, or a scheduled `hcloud` call)
- `enable_backups = true` in Terraform — full server snapshots
- Off-site sync: `rsync /data/backups` to object storage on a cron

### Restore

```bash
# Database
gunzip -c /data/backups/pg-<id>-<stamp>.sql.gz | \
  docker exec -i <postgres-container> psql -U agenticir -d postgres

# Coolify state — stop Coolify first
tar xzf /data/backups/coolify-<stamp>.tar.gz -C /data
```

Restoring Postgres restores LangGraph checkpoints too, so in-flight
investigations resume from wherever they were.

---

## Upgrades

**Application** — push to `main`; the deploy workflow redeploys. Or manually:

```bash
make coolify-redeploy      # rebuild and restart the existing resource
```

**Base images** (n8n, Postgres, Redis) — pinned in
`docker-compose.coolify.yml`. Change the tag, commit, deploy.
Read the Postgres release notes before crossing a major version; a major upgrade
needs a dump/restore, not a tag bump.

**Coolify** — self-updates by default, or from Settings in its UI.

**Host packages** — unattended-upgrades applies security patches nightly and
reboots at 04:30 UTC when the kernel requires it. Containers come back on their
own (`restart: unless-stopped`), and in-flight runs resume from their last
checkpoint.

---

## Cost control

LLM spend is the dominant cost. Levers, in order of effect:

1. **`MAX_INVESTIGATION_ROUNDS`** — each round is a full fan-out. Dropping 3 → 2
   removes roughly a third of the token spend.
2. **`MAX_PARALLEL_SPECIALISTS`** — caps fan-out width per round.
3. **`LLM_MODEL_SPECIALIST`** — specialists do the highest call volume. Keep them
   on a small fast model and reserve the strong model for supervisor and critic.
4. **Filter earlier.** The n8n intake workflow drops low-severity alerts before
   they reach an agent. Tune that threshold to your volume — it is free.
5. **`LANGSMITH_TRACING=true`** to see exactly where tokens go.

`_MAX_CONCURRENT_RUNS` in `app/services/runner.py` (default 8) bounds how many
investigations run at once, which caps both burst spend and memory.

---

## Common problems

**Investigations fail immediately**
Almost always the LLM key. Check `GET /v1/incidents/<id>` — errors are recorded
on the incident. Also check provider rate limits; specialists fan out, so one
alert can be 4+ concurrent calls.

**Slack stopped responding**
Signature verification fails closed. Check `SLACK_SIGNING_SECRET` matches the
app, and that the bot is still in the channel. Slack disables Event
subscriptions after sustained failures — re-enable in the app config.
`docker logs` on the api container shows `slack.verify_*` warnings with a reason.

**Everything is slow**
`docker stats` on the host. Postgres is capped at 3 GB and the API at 3 GB in the
compose file. If both are pinned, resize the server (`server_type = "cax41"`) and
apply — `/data` reattaches on reboot.

**Disk filling up**
```bash
ssh root@$SERVER_IP df -h /data
ssh root@$SERVER_IP du -sh /data/* | sort -h
```
Weekly image pruning is installed. The usual culprits are n8n execution history
(pruned to 14 days by `EXECUTIONS_DATA_MAX_AGE`) and old backups. LangGraph
checkpoints grow with investigation count — there is no automatic pruning, by
design, since they are the audit trail. Grow the volume in the Hetzner console,
then `resize2fs` on the host.

**The channel sweep is not picking anything up**
Run it by hand and read the counts:
```bash
curl -s -X POST -H "X-API-Key: $API_KEY" https://$APP_FQDN/v1/slack/poll
# {"channels":1,"candidates":3,"actions":1,"dispositions":{"update_incident":1,"ignore":2}}
```
`channels: 0` means the channel never resolved — grant `channels:read`, or set
`SLACK_POLL_CHANNELS` to the raw id (`C0…`), which needs no extra scope.
`candidates: 0` with traffic in the channel means either the bot lacks
`channels:history`, or every message was already claimed — claims are in
`slack_seen_messages`, one row per message the bot took responsibility for.
`actions: 0` with candidates means the classifier chose `ignore`, which it is
told to prefer; `poller.budget_reached` in the logs means `SLACK_POLL_MAX_ACTIONS`
capped the sweep and the rest were deferred to the next one.

**The bot answered the same message twice**
It shouldn't: the Events API and the sweep both claim a message before acting,
and the claim is a primary-key insert. If it happens, look for
`slack_watch.requeued_stale` — a claim orphaned by a crash is offered round again
after 15 minutes, which is deliberate, since the alternative is dropping it.

**An investigation is wedged in `running`**
It survived a restart but nothing resumed it. Inspect the graph state directly:
```bash
curl -s -H "X-API-Key: $API_KEY" https://$APP_FQDN/v1/incidents/<id>/state | jq '.next'
```
`next` shows which node it would execute. Non-empty means the checkpoint is
intact and resumable.

---

## Security maintenance

- **Rotate `API_KEY`**: change `SERVICE_BASE64_64_APIKEY` in Coolify, redeploy,
  update anything that calls `/v1` (n8n credentials, CI secrets).
- **Rotate the Slack signing secret** from the Slack app config, then update
  Coolify and redeploy.
- **Review `admin_ips`** when people join or leave. It is the only thing between
  the internet and your Coolify dashboard.
- **Audit approvals**: every containment decision records the approver and a
  timestamp on the incident timeline. `GET /v1/incidents/<id>` returns it.
- **Check fail2ban**: `ssh root@$SERVER_IP fail2ban-client status sshd`

---

## Tuning agent behaviour

Prompts live in `app/graph/prompts.py` — one file, no graph changes needed.
Common adjustments:

- **Too many false escalations** → strengthen the alternative-explanations
  instruction in `CRITIC`, or raise `AUTO_APPROVE_SEVERITY_BELOW`.
- **Investigations close too early** → the critic is being lenient; make its
  gap-checking stricter, or raise `MAX_INVESTIGATION_ROUNDS`.
- **Reports too verbose for Slack** → tighten the structure in `REPORT`.
- **A specialist is not pulling its weight** → sharpen its objective wording in
  `SUPERVISOR`, which is what actually drives dispatch.
- **The sweep acts on too much chatter** → the bias toward `ignore` lives in
  `TRIAGE_PROMPT` in `app/slack/poller.py`; lowering `SLACK_POLL_MAX_ACTIONS`
  caps the damage of a bad cycle without touching the prompt.
- **The thread is too noisy during a run** → `SLACK_PROGRESS_UPDATES=false`
  leaves the acknowledgement and the final report and drops the narration.

Adding a specialist takes three edits: a prompt in `prompts.py`, an entry in
`_PROMPT_BY_SPECIALIST` in `nodes/specialist.py`, and its name in
`ALL_SPECIALISTS` in `graph/state.py`. The fan-out picks it up automatically.
