# Coolify deployment

Two files matter here:

| File | Role |
|---|---|
| `docker-compose.coolify.yml` | The production stack Coolify deploys |
| `bootstrap.py` | Creates the project + resource, syncs env, triggers deploy |

## Coolify conventions this stack relies on

**Magic variables.** Coolify substitutes these at deploy time and persists the
generated values, so secrets never live in the repo and survive redeploys:

| Pattern | Effect |
|---|---|
| `SERVICE_FQDN_<SERVICE>_<PORT>` | Assigns a domain, writes proxy labels, provisions TLS |
| `SERVICE_PASSWORD_<NAME>` | Generates and persists a password |
| `SERVICE_BASE64_64_<NAME>` | Generates a 64-byte base64 secret |

Used here: `SERVICE_FQDN_API_8000`, `SERVICE_FQDN_N8N_5678`,
`SERVICE_PASSWORD_POSTGRES`, `SERVICE_BASE64_64_APIKEY`,
`SERVICE_BASE64_64_N8NTOKEN`, `SERVICE_BASE64_64_N8NENCRYPTION`.

The service-name part is uppercased with non-alphanumerics stripped: service
`api` on port 8000 → `SERVICE_FQDN_API_8000`. **Renaming a service in the compose
file renames its magic variables**, which orphans the generated values — expect a
new API key and a new Postgres password if you do it.

**Rules the compose file follows:**

- No `container_name` — Coolify manages naming
- No host `ports:` — only the proxy is externally reachable
- Named volumes, namespaced per resource automatically
- Only services with a `SERVICE_FQDN_*` are exposed publicly; `postgres` and
  `redis` have none and stay on the internal network

## bootstrap.py

Stdlib only, so it runs on a bare machine or in CI with no `pip install`.

```bash
export COOLIFY_URL=https://coolify.example.com   # or http://<ip>:8000
export COOLIFY_API_TOKEN=...
export APP_FQDN=app.example.com
export N8N_FQDN=n8n.example.com
export GIT_REPOSITORY=https://github.com/<you>/AgenticIR
export ANTHROPIC_API_KEY=sk-ant-...

python infra/coolify/bootstrap.py
```

| Flag | Effect |
|---|---|
| `--deploy-only` | Skip reconciliation, just redeploy |
| `--force` | Rebuild without cache |
| `--no-wait` | Return once the deploy is queued |
| `--insecure` | Skip TLS verification (bring-up against a self-signed cert only) |
| `--server <name\|uuid\|ip>` | Pick a server when several are registered |

It reconciles rather than recreates: existing project and resource are reused,
environment variables are diffed and only changed keys are written. Safe to run
on every push.

Variables in `PASSTHROUGH_ENV` are copied from your shell into the Coolify
resource when set. Secrets are redacted in the console output.

## If the API disagrees with your Coolify version

Coolify's REST API moves between releases. If resource creation returns a 4xx,
the script prints the response body and tells you to create the resource once by
hand:

> Project → **+ New** → **Docker Compose** (from a Git repository)
> Compose path: `/infra/coolify/docker-compose.coolify.yml`

Re-run the script afterwards — it finds the resource by name and only syncs
environment variables and deploys, which are the stable parts of the API.
