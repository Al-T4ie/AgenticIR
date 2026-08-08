#!/usr/bin/env python3
"""Create and deploy the AgenticIR stack on a Coolify server, via its REST API.

Idempotent: re-running reconciles the project, resource and environment
variables, then triggers a deploy. Safe to run from CI.

    export COOLIFY_URL=https://coolify.example.com     # or http://<ip>:8000
    export COOLIFY_API_TOKEN=...                       # Coolify → Keys & Tokens
    export APP_FQDN=app.example.com
    export N8N_FQDN=n8n.example.com
    export ANTHROPIC_API_KEY=sk-ant-...
    python infra/coolify/bootstrap.py

Stdlib only, so it runs on a bare operator machine or in a CI container with no
pip install step.
"""

from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

# ── Defaults ─────────────────────────────────────────────────────────────────
DEFAULT_PROJECT = "agentic-ir"
DEFAULT_ENVIRONMENT = "production"
DEFAULT_RESOURCE = "agenticir-stack"
DEFAULT_COMPOSE_PATH = "infra/coolify/docker-compose.coolify.yml"
DEFAULT_BRANCH = "main"

# Passed through to the Coolify resource when present in the caller's env.
PASSTHROUGH_ENV = [
    "LLM_PROVIDER",
    "ANTHROPIC_API_KEY",
    "OPENROUTER_API_KEY",
    "OPENROUTER_BASE_URL",
    "OPENAI_API_KEY",
    "OPENAI_BASE_URL",
    "OLLAMA_BASE_URL",
    "LLM_MODEL_SUPERVISOR",
    "LLM_MODEL_SPECIALIST",
    "LLM_MODEL_CRITIC",
    "MAX_INVESTIGATION_ROUNDS",
    "MAX_PARALLEL_SPECIALISTS",
    "REQUIRE_APPROVAL_FOR_CONTAINMENT",
    "AUTO_APPROVE_SEVERITY_BELOW",
    "SLACK_ENABLED",
    "SLACK_BOT_TOKEN",
    "SLACK_SIGNING_SECRET",
    "SLACK_DEFAULT_CHANNEL",
    "N8N_ENABLED",
    "N8N_TOOLS",
    # Only used by the external-n8n compose variant; harmless otherwise, since
    # the bundled stack overrides both in the compose file itself.
    "N8N_BASE_URL",
    "N8N_WEBHOOK_TOKEN",
    "LANGSMITH_TRACING",
    "LANGSMITH_API_KEY",
    "LANGSMITH_ENDPOINT",
    "LANGSMITH_PROJECT",
    "LOG_LEVEL",
    "WEB_CONCURRENCY",
    "CORS_ORIGINS",
    "TZ",
]

SECRET_KEYS = {
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "SLACK_BOT_TOKEN",
    "SLACK_SIGNING_SECRET",
    "LANGSMITH_API_KEY",
    "COOLIFY_API_TOKEN",
    "OPENROUTER_API_KEY",
    "N8N_WEBHOOK_TOKEN",
}


# ── Output helpers ───────────────────────────────────────────────────────────
class C:
    OK = "\033[32m"
    WARN = "\033[33m"
    ERR = "\033[31m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    END = "\033[0m"


def _tty() -> bool:
    return sys.stdout.isatty()


def say(msg: str, colour: str = "") -> None:
    print(f"{colour if _tty() else ''}{msg}{C.END if _tty() and colour else ''}", flush=True)


def step(msg: str) -> None:
    say(f"\n▸ {msg}", C.BOLD)


def ok(msg: str) -> None:
    say(f"  ✓ {msg}", C.OK)


def warn(msg: str) -> None:
    say(f"  ! {msg}", C.WARN)


def die(msg: str, hint: str = "") -> None:
    say(f"\n✗ {msg}", C.ERR)
    if hint:
        say(f"  {hint}", C.DIM)
    sys.exit(1)


def redact(key: str, value: str) -> str:
    if key in SECRET_KEYS or "TOKEN" in key or "SECRET" in key or "PASSWORD" in key:
        return f"{value[:4]}…{value[-2:]}" if len(value) > 8 else "…"
    return value


# ── Coolify client ───────────────────────────────────────────────────────────
class Coolify:
    def __init__(self, base_url: str, token: str, insecure: bool = False, timeout: int = 60):
        base = base_url.strip().rstrip("/")
        if not base.startswith(("http://", "https://")):
            # A schemeless value otherwise dies deep inside urllib with
            # "unknown url type", which reads like a bug rather than a typo.
            die(
                f"COOLIFY_URL must start with http:// or https:// — got {base_url!r}",
                "e.g. https://coolify.example.com, or http://<ip>:8000 during bring-up.",
            )
        # Coolify's dashboard lives at the root; people paste the /api/v1 path
        # or a deep link, and both would otherwise produce confusing 404s.
        for suffix in ("/api/v1", "/api"):
            if base.endswith(suffix):
                base = base[: -len(suffix)]
        self.base = base
        self.api = f"{self.base}/api/v1"
        self.token = token
        self.timeout = timeout
        self.ctx: ssl.SSLContext | None = None
        if insecure:
            # Only for the initial bring-up window, when Coolify is still on a
            # self-signed cert at https://<ip>:8000.
            self.ctx = ssl.create_default_context()
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

    def request(
        self, method: str, path: str, body: dict[str, Any] | None = None, quiet: bool = False
    ) -> Any:
        url = f"{self.api}{path}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", f"Bearer {self.token}")
        req.add_header("Accept", "application/json")
        if data:
            req.add_header("Content-Type", "application/json")

        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as resp:
                raw = resp.read().decode()
                return json.loads(raw) if raw.strip() else {}
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode()[:600]
            if quiet:
                raise
            if exc.code == 401:
                die(
                    "Coolify rejected the API token (401).",
                    "Create a token in Coolify → Keys & Tokens → API tokens, with read+write.",
                )
            if exc.code == 404:
                raise
            die(f"{method} {path} failed: HTTP {exc.code}", detail)
        except urllib.error.URLError as exc:
            die(
                f"Could not reach Coolify at {self.base}: {exc.reason}",
                "Check COOLIFY_URL, that the server finished installing (make coolify-wait), "
                "and that your IP is in admin_ips.",
            )
        return None

    def get(self, path: str, quiet: bool = False) -> Any:
        return self.request("GET", path, quiet=quiet)

    def post(self, path: str, body: dict[str, Any], quiet: bool = False) -> Any:
        return self.request("POST", path, body, quiet=quiet)

    def patch(self, path: str, body: dict[str, Any], quiet: bool = False) -> Any:
        return self.request("PATCH", path, body, quiet=quiet)


def unwrap(payload: Any) -> list[dict[str, Any]]:
    """Coolify returns bare lists on some endpoints and {"data": [...]} on others."""
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("data", "items", "results"):
            if isinstance(payload.get(key), list):
                return payload[key]
        return [payload]
    return []


# ── Reconciliation steps ─────────────────────────────────────────────────────
def pick_server(client: Coolify, wanted: str | None) -> dict[str, Any]:
    servers = unwrap(client.get("/servers"))
    if not servers:
        die(
            "Coolify reports no servers.",
            "Finish the Coolify onboarding wizard in the browser first — it registers localhost.",
        )

    if wanted:
        for srv in servers:
            if wanted in (srv.get("uuid"), srv.get("name"), srv.get("ip")):
                return srv
        die(
            f"No Coolify server matches '{wanted}'.",
            "Available: " + ", ".join(f"{s.get('name')} ({s.get('uuid')})" for s in servers),
        )

    if len(servers) > 1:
        warn(f"{len(servers)} servers registered; using the first. Pass --server to choose.")
    return servers[0]


def find_project(client: Coolify, name: str) -> dict[str, Any] | None:
    """Match case-insensitively — Coolify preserves the casing a human typed,
    and creating a near-duplicate project is a confusing side effect."""
    wanted = name.strip().casefold()
    for proj in unwrap(client.get("/projects")):
        if str(proj.get("name", "")).strip().casefold() == wanted:
            return proj
    return None


def ensure_project(client: Coolify, name: str) -> dict[str, Any]:
    existing = find_project(client, name)
    if existing is not None:
        ok(f"project '{existing.get('name')}' already exists ({existing.get('uuid')})")
        return existing

    created = client.post(
        "/projects",
        {"name": name, "description": "Agentic incident response platform"},
    )
    uuid = created.get("uuid") if isinstance(created, dict) else None
    if not uuid:
        die("Project creation returned no uuid", json.dumps(created)[:400])
    ok(f"created project '{name}' ({uuid})")
    return {"name": name, "uuid": uuid}


def find_resource(client: Coolify, project_uuid: str, name: str) -> dict[str, Any] | None:
    """Look for an existing compose resource by name inside the project."""
    try:
        detail = client.get(f"/projects/{project_uuid}", quiet=True)
    except urllib.error.HTTPError:
        detail = {}

    environments = (detail or {}).get("environments") or []
    for env in environments:
        for key in ("applications", "services", "resources"):
            for res in env.get(key, []) or []:
                if res.get("name") == name:
                    return res

    # Fall back to the flat applications listing.
    try:
        for app in unwrap(client.get("/applications", quiet=True)):
            if app.get("name") == name:
                return app
    except urllib.error.HTTPError:
        pass
    return None


def create_resource(
    client: Coolify,
    *,
    name: str,
    project_uuid: str,
    server_uuid: str,
    environment: str,
    repo: str,
    branch: str,
    compose_path: str,
) -> dict[str, Any]:
    payload = {
        "name": name,
        "description": "AgenticIR: LangGraph agents, API, dashboard, n8n",
        "project_uuid": project_uuid,
        "server_uuid": server_uuid,
        "environment_name": environment,
        "git_repository": repo,
        "git_branch": branch,
        "build_pack": "dockercompose",
        "docker_compose_location": (
            compose_path if compose_path.startswith("/") else f"/{compose_path}"
        ),
        "ports_exposes": "8000",
        "instant_deploy": False,
    }
    try:
        created = client.post("/applications/public", payload, quiet=True)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode()[:800]
        die(
            f"Could not create the Coolify resource (HTTP {exc.code}).",
            f"{detail}\n\n"
            "  If your Coolify version's API differs, create the resource once by hand:\n"
            "    Project → + New → Docker Compose (from a Git repository)\n"
            f"    repo={repo} branch={branch} compose={compose_path}\n"
            "  then re-run this script — it will find it by name and only sync env vars.",
        )
    uuid = created.get("uuid") if isinstance(created, dict) else None
    if not uuid:
        die("Resource creation returned no uuid", json.dumps(created)[:400])
    ok(f"created resource '{name}' ({uuid})")
    return created


def existing_env_keys(client: Coolify, resource_uuid: str) -> dict[str, str]:
    try:
        rows = unwrap(client.get(f"/applications/{resource_uuid}/envs", quiet=True))
    except urllib.error.HTTPError:
        return {}
    return {r["key"]: r.get("value", "") for r in rows if isinstance(r, dict) and r.get("key")}


def sync_env(client: Coolify, resource_uuid: str, desired: dict[str, str]) -> None:
    current = existing_env_keys(client, resource_uuid)
    created = updated = skipped = 0

    for key, value in desired.items():
        if value == "":
            continue
        if current.get(key) == value:
            skipped += 1
            continue

        body = {
            "key": key,
            "value": value,
            "is_preview": False,
            "is_build_time": False,
            "is_literal": False,
        }
        if key in current:
            try:
                client.patch(f"/applications/{resource_uuid}/envs", body, quiet=True)
                updated += 1
            except urllib.error.HTTPError as exc:
                warn(f"could not update {key}: HTTP {exc.code}")
        else:
            try:
                client.post(f"/applications/{resource_uuid}/envs", body, quiet=True)
                created += 1
            except urllib.error.HTTPError as exc:
                warn(f"could not create {key}: HTTP {exc.code}")

    ok(f"environment synced — {created} created, {updated} updated, {skipped} unchanged")


def deploy(client: Coolify, resource_uuid: str, force: bool = False) -> str:
    query = urllib.parse.urlencode({"uuid": resource_uuid, "force": str(force).lower()})
    result = client.get(f"/deploy?{query}")
    deployments = unwrap(result)
    dep_uuid = ""
    for dep in deployments:
        dep_uuid = dep.get("deployment_uuid") or dep.get("uuid") or ""
        if dep_uuid:
            break
    ok(f"deployment queued{f' ({dep_uuid})' if dep_uuid else ''}")
    return dep_uuid


def wait_for_health(url: str, timeout: int, insecure: bool) -> bool:
    """Poll the app's /health until it answers or we give up."""
    ctx = None
    if insecure or url.startswith("https://"):
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

    deadline = time.time() + timeout
    attempt = 0
    while time.time() < deadline:
        attempt += 1
        try:
            with urllib.request.urlopen(f"{url}/health", timeout=10, context=ctx) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            pass
        remaining = int(deadline - time.time())
        print(
            f"\r  … waiting for {url}/health ({remaining}s left, attempt {attempt})",
            end="",
            flush=True,
        )
        time.sleep(10)
    print()
    return False


# ── Main ─────────────────────────────────────────────────────────────────────
def main() -> int:
    parser = argparse.ArgumentParser(description="Deploy AgenticIR to Coolify")
    parser.add_argument("--coolify-url", default=os.getenv("COOLIFY_URL", ""))
    parser.add_argument("--token", default=os.getenv("COOLIFY_API_TOKEN", ""))
    parser.add_argument("--project", default=os.getenv("COOLIFY_PROJECT", DEFAULT_PROJECT))
    parser.add_argument(
        "--environment", default=os.getenv("COOLIFY_ENVIRONMENT", DEFAULT_ENVIRONMENT)
    )
    parser.add_argument("--resource-name", default=os.getenv("COOLIFY_RESOURCE", DEFAULT_RESOURCE))
    parser.add_argument("--server", default=os.getenv("COOLIFY_SERVER", ""))
    parser.add_argument("--repo", default=os.getenv("GIT_REPOSITORY", ""))
    parser.add_argument("--branch", default=os.getenv("GIT_BRANCH", DEFAULT_BRANCH))
    parser.add_argument("--compose-path", default=os.getenv("COMPOSE_PATH", DEFAULT_COMPOSE_PATH))
    parser.add_argument("--app-fqdn", default=os.getenv("APP_FQDN", ""))
    parser.add_argument("--n8n-fqdn", default=os.getenv("N8N_FQDN", ""))
    parser.add_argument(
        "--deploy-only", action="store_true", help="Skip reconciliation, just deploy"
    )
    parser.add_argument("--force", action="store_true", help="Force rebuild without cache")
    parser.add_argument("--no-wait", action="store_true", help="Do not wait for the app to come up")
    parser.add_argument("--wait-timeout", type=int, default=600)
    parser.add_argument(
        "--insecure", action="store_true", help="Skip TLS verification (bring-up only)"
    )
    args = parser.parse_args()

    if not args.coolify_url:
        die(
            "COOLIFY_URL is not set.",
            'eval "$(terraform -chdir=infra/terraform output -raw bootstrap_env)"',
        )
    if not args.token:
        die("COOLIFY_API_TOKEN is not set.", "Create one in Coolify → Keys & Tokens → API tokens.")

    client = Coolify(args.coolify_url, args.token, insecure=args.insecure)

    step(f"Connecting to Coolify at {args.coolify_url}")
    try:
        version = client.get("/version", quiet=True)
        ok(f"Coolify {version if isinstance(version, str) else json.dumps(version)[:60]}")
    except Exception:
        # /version is not present on every build; the servers call below is the
        # real connectivity + auth check.
        warn("could not read /version; continuing")

    server = pick_server(client, args.server or None)
    ok(f"server: {server.get('name')} ({server.get('ip', '?')})")

    if args.deploy_only:
        # Strictly read-then-deploy: this path must not create a project or a
        # resource, or a "just redeploy" invocation silently reshapes the account.
        project = find_project(client, args.project)
        if project is None:
            die(
                f"No project named '{args.project}' to deploy into.",
                "Run without --deploy-only first to create it.",
            )
        resource = find_resource(client, project["uuid"], args.resource_name)
        if not resource:
            die(
                f"No resource named '{args.resource_name}' to deploy.",
                "Run without --deploy-only first.",
            )
        step("Triggering deployment")
        deploy(client, resource["uuid"], args.force)
        return 0

    project = ensure_project(client, args.project)
    project_uuid = project["uuid"]

    # ── Resource ──
    step(f"Reconciling resource '{args.resource_name}'")
    resource = find_resource(client, project_uuid, args.resource_name)
    if resource:
        ok(f"resource already exists ({resource.get('uuid')})")
    else:
        if not args.repo:
            die(
                "GIT_REPOSITORY is not set and the resource does not exist yet.",
                "Coolify builds from a git repo — pass --repo https://github.com/<owner>/<repo>",
            )
        resource = create_resource(
            client,
            name=args.resource_name,
            project_uuid=project_uuid,
            server_uuid=server["uuid"],
            environment=args.environment,
            repo=args.repo,
            branch=args.branch,
            compose_path=args.compose_path,
        )
    resource_uuid = resource["uuid"]

    # ── Environment ──
    step("Syncing environment variables")
    desired: dict[str, str] = {}

    if args.app_fqdn:
        desired["SERVICE_FQDN_API_8000"] = _as_url(args.app_fqdn)
    if args.n8n_fqdn:
        desired["SERVICE_FQDN_N8N_5678"] = _as_url(args.n8n_fqdn)

    for key in PASSTHROUGH_ENV:
        value = os.getenv(key, "")
        if value:
            desired[key] = value

    if not any(
        desired.get(k) for k in ("ANTHROPIC_API_KEY", "OPENROUTER_API_KEY", "OPENAI_API_KEY")
    ):
        warn(
            "no LLM API key in the environment — the stack will deploy but every "
            "investigation will fail until you set one in Coolify."
        )

    for key, value in sorted(desired.items()):
        say(f"  {key} = {redact(key, value)}", C.DIM)
    sync_env(client, resource_uuid, desired)

    # ── Deploy ──
    step("Triggering deployment")
    deploy(client, resource_uuid, args.force)

    if args.no_wait or not args.app_fqdn:
        say("\nDone. Watch progress in the Coolify UI.", C.OK)
        return 0

    step("Waiting for the application to answer")
    app_url = _as_url(args.app_fqdn)
    if wait_for_health(app_url, args.wait_timeout, args.insecure):
        say(f"\n✓ AgenticIR is live at {app_url}/ui", C.OK)
        say(f"  API docs:  {app_url}/docs", C.DIM)
        if args.n8n_fqdn:
            say(f"  n8n:       {_as_url(args.n8n_fqdn)}", C.DIM)
        say(
            "\n  The dashboard API key is the generated API_KEY value —\n"
            "  read it from Coolify → resource → Environment Variables.",
            C.DIM,
        )
        return 0

    warn(
        f"{app_url}/health did not answer within {args.wait_timeout}s.\n"
        "  The build may still be running — check the Coolify deployment logs.\n"
        "  If DNS is not pointing at the server yet, TLS issuance will keep failing."
    )
    return 1


def _as_url(fqdn: str) -> str:
    if fqdn.startswith(("http://", "https://")):
        return fqdn.rstrip("/")
    return f"https://{fqdn.rstrip('/')}"


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        say("\nInterrupted.", C.WARN)
        raise SystemExit(130) from None
