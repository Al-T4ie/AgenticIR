#!/usr/bin/env bash
# One-shot deploy to an existing Coolify.
#
# Run this from a machine that can reach your Coolify instance — your laptop or
# the Coolify host itself. Secrets come from the environment; nothing is written
# to disk and nothing is committed.
#
#   export COOLIFY_URL='https://coolify.example.com'
#   export COOLIFY_API_TOKEN='...'
#   export APP_FQDN='ir.example.com'
#   export N8N_FQDN='ir-n8n.example.com'
#   export GIT_REPOSITORY='https://github.com/you/AgenticIR'
#   export GIT_BRANCH='main'
#   export LLM_PROVIDER='openrouter'
#   export OPENROUTER_API_KEY='sk-or-v1-...'
#   bash infra/scripts/deploy.sh
#
# Re-running is safe: the bootstrap reconciles rather than recreates.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# ── Preflight ────────────────────────────────────────────────────────────────
missing=()
for v in COOLIFY_URL COOLIFY_API_TOKEN APP_FQDN GIT_REPOSITORY; do
  [[ -z "${!v:-}" ]] && missing+=("$v")
done
if (( ${#missing[@]} )); then
  echo "Missing required environment: ${missing[*]}" >&2
  echo "See the header of this script, or docs/DEMO.md." >&2
  exit 2
fi

export LLM_PROVIDER="${LLM_PROVIDER:-anthropic}"

case "$LLM_PROVIDER" in
  anthropic)
    [[ -n "${ANTHROPIC_API_KEY:-}" ]] || { echo "LLM_PROVIDER=anthropic needs ANTHROPIC_API_KEY" >&2; exit 2; }
    ;;
  openrouter)
    # Accept either spelling, then normalise to the documented name.
    export OPENROUTER_API_KEY="${OPENROUTER_API_KEY:-${OPENROUTER_API_TOKEN:-}}"
    [[ -n "$OPENROUTER_API_KEY" ]] || { echo "LLM_PROVIDER=openrouter needs OPENROUTER_API_KEY" >&2; exit 2; }

    # OpenRouter model IDs are namespaced; the bare defaults 404. Refuse to
    # deploy a stack that would fail on its first investigation.
    for v in LLM_MODEL_SUPERVISOR LLM_MODEL_SPECIALIST LLM_MODEL_CRITIC; do
      val="${!v:-}"
      if [[ -z "$val" || "$val" != */* ]]; then
        echo "LLM_PROVIDER=openrouter requires namespaced model IDs." >&2
        echo "  $v is '${val:-<unset>}' — expected something like anthropic/claude-sonnet-5" >&2
        echo "  Check https://openrouter.ai/models for the exact IDs." >&2
        exit 2
      fi
    done

    # Every role emits structured output or drives a tool loop, so a model
    # without tool support fails mid-investigation with an opaque 400. Catch it
    # here instead. Advisory only — a network hiccup must not block a deploy.
    if command -v python3 >/dev/null 2>&1; then
      catalogue=$(curl -sS --max-time 20 -H "Authorization: Bearer ${OPENROUTER_API_KEY}" \
        https://openrouter.ai/api/v1/models 2>/dev/null || true)
      if [[ -n "$catalogue" ]]; then
        printf '%s' "$catalogue" | MODELS="${LLM_MODEL_SUPERVISOR},${LLM_MODEL_SPECIALIST},${LLM_MODEL_CRITIC}" \
          python3 -c '
import json, os, sys
try:
    known = {m["id"]: m for m in json.load(sys.stdin)["data"]}
except Exception:
    sys.exit(0)  # unparseable catalogue is not a deploy blocker
for mid in os.environ["MODELS"].split(","):
    m = known.get(mid)
    if m is None:
        print(f"  ! {mid} is not in the OpenRouter catalogue — calls will 404")
    elif "tools" not in (m.get("supported_parameters") or []):
        print(f"  ! {mid} does not advertise tool support — structured output will fail")
' || true
      fi
    fi
    ;;
  openai)
    [[ -n "${OPENAI_API_KEY:-}" ]] || { echo "LLM_PROVIDER=openai needs OPENAI_API_KEY" >&2; exit 2; }
    ;;
esac

COMPOSE_PATH="${COMPOSE_PATH:-infra/coolify/docker-compose.coolify.yml}"
if [[ -n "${N8N_BASE_URL:-}" ]]; then
  COMPOSE_PATH="infra/coolify/docker-compose.external-n8n.yml"
  [[ -n "${N8N_WEBHOOK_TOKEN:-}" ]] || {
    echo "Using an external n8n requires N8N_WEBHOOK_TOKEN (any strong random string)." >&2
    echo "  Generate one with: openssl rand -hex 32" >&2
    exit 2
  }
fi
export COMPOSE_PATH

export GIT_BRANCH="${GIT_BRANCH:-main}"
export N8N_ENABLED="${N8N_ENABLED:-true}"
export SLACK_ENABLED="${SLACK_ENABLED:-false}"

echo "▸ Deploying"
echo "    Coolify   ${COOLIFY_URL}"
echo "    App       https://${APP_FQDN}"
[[ -n "${N8N_FQDN:-}" ]]     && echo "    n8n       https://${N8N_FQDN}"
[[ -n "${N8N_BASE_URL:-}" ]] && echo "    n8n       ${N8N_BASE_URL} (external)"
echo "    Repo      ${GIT_REPOSITORY} @ ${GIT_BRANCH}"
echo "    Compose   ${COMPOSE_PATH}"
echo "    LLM       ${LLM_PROVIDER}"
echo

python3 "${HERE}/infra/coolify/bootstrap.py" --compose-path "${COMPOSE_PATH}" "$@"

cat <<EOF

▸ Next
    1. Read the generated API_KEY from Coolify → resource → Environment Variables.
    2. Smoke test:
         BASE_URL=https://${APP_FQDN} API_KEY='<that key>' bash infra/scripts/smoke-test.sh
    3. Import the n8n workflows from infra/n8n/workflows/ and activate them.
    4. Seed the demo:
         BASE_URL=https://${APP_FQDN} API_KEY='<that key>' bash infra/scripts/demo-seed.sh
EOF
