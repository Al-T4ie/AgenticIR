# Deploying AgenticIR to Hetzner with Coolify

From an empty Hetzner project to a running platform. Budget 30–40 minutes,
most of it waiting for cloud-init and the first container build.

---

## What you need

| | |
|---|---|
| Hetzner Cloud API token | Console → Security → API tokens → **Read & Write** |
| SSH keypair | `ssh-keygen -t ed25519 -C agenticir` |
| Your public IP | `curl -s https://ifconfig.me` |
| An LLM API key | Anthropic or OpenAI (or run Ollama locally) |
| Terraform ≥ 1.6 | |
| A domain | Optional — without one the stack uses `sslip.io` |

**Cost**: `cax31` (8 vCPU ARM / 16 GB) ≈ €13/mo, +20% with backups, plus ~€2.40/mo
for a 50 GB volume. Under €20/mo before LLM usage.

---

## 1. Provision the server

```bash
cd infra/terraform
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars`:

```hcl
hcloud_token   = "..."                        # or export TF_VAR_hcloud_token
ssh_public_key = "ssh-ed25519 AAAA... you@example.com"
admin_ips      = ["203.0.113.4/32"]           # your egress — NOT 0.0.0.0/0
base_domain    = ""                           # empty → sslip.io fallback
```

`admin_ips` has no default on purpose: it gates SSH *and* the Coolify dashboard.
If your address is dynamic, use your VPN's egress range, or widen it temporarily
and narrow it once you are in.

```bash
terraform init
terraform apply
```

Terraform creates the SSH key, private network, data volume, firewall, server and
floating IP, then prints a `next_steps` block with every URL you need.

> The data volume is declared `prevent_destroy`. `terraform destroy` will refuse
> until you remove that lifecycle block — deliberate friction, because the volume
> holds every incident record and checkpoint.

## 2. Wait for Coolify

cloud-init hardens the host and runs the Coolify installer. 5–10 minutes.

```bash
eval "$(terraform -chdir=infra/terraform output -raw bootstrap_env)"
make coolify-wait
```

The script waits for SSH, then polls for `/var/lib/agenticir/bootstrap-complete`.
If bootstrap failed it prints the reason and the last 40 log lines instead of
hanging. To watch directly:

```bash
ssh root@$SERVER_IP tail -f /var/log/agenticir-bootstrap.log
```

## 3. Claim the Coolify instance

Open `http://<ip>:8000` **now**. The first visitor to a fresh Coolify instance
creates the admin account — don't leave that window open longer than necessary.
The port is firewalled to `admin_ips`, but claim it anyway.

Then: **Keys & Tokens → API tokens → Create**, with read/write. Copy it.

## 4. Point DNS (skip if using sslip.io)

```bash
terraform -chdir=infra/terraform output dns_records_required
```

Create those A records before deploying — Let's Encrypt validates over HTTP, so
TLS issuance fails if the names don't resolve yet.

## 5. Deploy the stack

```bash
eval "$(terraform -chdir=infra/terraform output -raw bootstrap_env)"
export COOLIFY_API_TOKEN='...'
export GIT_REPOSITORY='https://github.com/<you>/AgenticIR'
export ANTHROPIC_API_KEY='sk-ant-...'

make coolify-deploy
```

`infra/coolify/bootstrap.py` creates the project, creates a Docker Compose
resource pointed at your repo, syncs environment variables, triggers the deploy,
and waits for `/health`. It is idempotent — re-run it any time.

The first build takes several minutes (Python wheels, n8n image). Watch it in the
Coolify UI under the resource's Deployments tab.

### Getting the API key

Coolify generates `API_KEY` from `SERVICE_BASE64_64_APIKEY` on first deploy and
keeps it stable afterwards. Read it from the resource's **Environment Variables**
tab. That value is the dashboard login and the `X-API-Key` header for `/v1`.

## 6. Verify

```bash
BASE_URL=https://$APP_FQDN API_KEY='<from Coolify>' make smoke
```

This checks liveness, readiness, and that unauthenticated requests are rejected
on every protected route. Add `--full` to drive one real investigation end to end
(costs tokens):

```bash
BASE_URL=https://$APP_FQDN API_KEY='...' bash infra/scripts/smoke-test.sh --full
```

---

## 7. Connect Slack

1. https://api.slack.com/apps → **Create New App → From an app manifest**
2. Paste `infra/slack/manifest.yaml`, replacing `app.example.com` with your
   `APP_FQDN` in all three URLs
3. Install to workspace
4. In Coolify, set on the resource and redeploy:

   ```
   SLACK_ENABLED=true
   SLACK_BOT_TOKEN=xoxb-...          # OAuth & Permissions
   SLACK_SIGNING_SECRET=...          # Basic Information
   SLACK_DEFAULT_CHANNEL=#incident-response
   ```

5. Invite the bot: `/invite @IR Bot` in your channel

Slack verifies the Events URL on save, so the app must already be deployed and
serving HTTPS. If verification fails, check that `SLACK_SIGNING_SECRET` matches
and that `/slack/events` returns 401 (not 502) for an unsigned request.

Try it: `@IR Bot investigate repeated failed logins for svc-backup from 45.33.32.156`

## 8. Connect n8n

Open `https://$N8N_FQDN`, create the owner account, then **Workflows → Import
from file** for each template in `infra/n8n/workflows/`.

For the inbound workflow (`01-siem-alert-intake`), add a **Header Auth**
credential on the webhook node — that is what your SIEM will present.

For agent-callable tools (`02-agent-tool-enrich-ioc`), the Header Auth credential
must be `Authorization: Bearer <N8N_WEBHOOK_TOKEN>`, using the generated
`SERVICE_BASE64_64_N8NTOKEN` value from the Coolify env tab. Then register the
tool with the agents:

```
N8N_TOOLS=enrich_ioc:agentic-ir/enrich-ioc:Look up an IP/domain/hash in threat intel
```

Redeploy. The enrichment specialist will now call that workflow.

The shipped enrichment workflow is a **stub** that returns `not_checked` — wire
it to the intel providers you actually license. It deliberately reports "unknown"
rather than "clean", because a fabricated clean verdict silently suppresses real
detections.

---

## Continuous deployment

`.github/workflows/deploy.yml` runs the same bootstrap on every push to `main`.

Repository **secrets**: `COOLIFY_URL`, `COOLIFY_API_TOKEN`, `ANTHROPIC_API_KEY`,
`SLACK_BOT_TOKEN`, `SLACK_SIGNING_SECRET`, `AGENTICIR_API_KEY`.
Repository **variables**: `APP_FQDN`, `N8N_FQDN`, `SLACK_ENABLED`, `N8N_TOOLS`.

---

## Troubleshooting

**`make coolify-wait` fails with `volume-missing`**
The data volume never attached. Check `hcloud_volume_attachment` in the Terraform
state and that the volume is in the same location as the server. Bootstrap aborts
rather than silently writing Coolify state to the ephemeral root disk.

**Coolify dashboard unreachable on :8000**
Your IP is not in `admin_ips`, or it changed. Update `terraform.tfvars` and
`terraform apply` — the firewall updates without touching the server.

**Deploy succeeds, `/health` never answers**
Check the Coolify deployment log first. Most common causes: DNS not resolving to
the floating IP (so TLS never issues), or the api container crash-looping because
Postgres is not healthy. `docker ps -a` on the host shows which.

**Investigations start but always fail**
No LLM key, or an invalid one. `GET /v1/incidents/<id>` shows the recorded errors.

**`terraform apply` wants to replace the server**
`user_data` and `image` are in `ignore_changes` precisely to prevent this. If a
replacement is still planned, something else changed — check the plan output
before confirming, and remember the data volume is what carries your state.

**Slack events 401 in production but work locally**
The signing secret differs between environments, or a proxy is buffering and
altering the body. Signature verification runs on the *raw* body before parsing.

---

## Scaling up

The single-node design carries a real SOC's alert volume comfortably. When it
stops:

1. **Resize vertically.** `server_type = "cax41"` and apply. Hetzner reboots the
   server; `/data` reattaches and everything comes back.
2. **Move Postgres off-box** to a separate instance or managed database; point
   `POSTGRES_HOST` at it.
3. **Split the API from the workers.** Runs execute as background tasks in the
   API process today. Adding a queue-backed worker service is the next step, and
   the checkpointer already makes it safe.
4. **Raise n8n throughput** by scaling `n8n-worker` — it is already in queue mode
   behind Redis.
