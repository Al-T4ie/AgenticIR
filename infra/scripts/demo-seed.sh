#!/usr/bin/env bash
# Fire the demo scenarios at a running AgenticIR deployment and follow each
# investigation to its resting state.
#
#   BASE_URL=https://ir.example.com API_KEY=... bash infra/scripts/demo-seed.sh
#   BASE_URL=... API_KEY=... bash infra/scripts/demo-seed.sh 1     # just scenario 1
#
# Each scenario exercises a different path through the graph:
#   1  true positive   → containment proposed → pauses for human approval
#   2  false positive  → no actions proposed  → closes on its own
#   3  inconclusive    → conflicting evidence → escalates rather than guessing
#
# This costs real LLM tokens — a few cents per run on the default models.

set -uo pipefail

BASE_URL="${BASE_URL:-http://localhost:8000}"
API_KEY="${API_KEY:-}"
ONLY="${1:-}"
BASE_URL="${BASE_URL%/}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if [[ -z "$API_KEY" ]]; then
  echo "API_KEY is required. Read it from Coolify → resource → Environment Variables." >&2
  exit 2
fi

declare -a SCENARIOS=(
  "1|demo-01-true-positive.json|true positive — expect containment + approval pause"
  "2|demo-02-false-positive.json|false positive — expect no actions, closes clean"
  "3|demo-03-inconclusive.json|inconclusive — expect escalation, not a guess"
)

started=()

for entry in "${SCENARIOS[@]}"; do
  IFS='|' read -r num file desc <<<"$entry"
  [[ -n "$ONLY" && "$ONLY" != "$num" ]] && continue

  path="$HERE/examples/$file"
  if [[ ! -f "$path" ]]; then
    echo "  ✗ missing $path" >&2
    continue
  fi

  echo
  echo "▸ Scenario $num: $desc"

  payload=$(printf '{"source":"demo","alert":%s}' "$(cat "$path")")
  body=$(curl -sS --max-time 30 -X POST "${BASE_URL}/v1/incidents" \
    -H "X-API-Key: ${API_KEY}" -H 'Content-Type: application/json' \
    -d "$payload" 2>/dev/null)

  id=$(printf '%s' "$body" | sed -n 's/.*"incident_id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
  if [[ -z "$id" ]]; then
    echo "  ✗ failed to start: ${body:0:300}" >&2
    continue
  fi
  echo "  started $id"
  started+=("$id")
done

if (( ${#started[@]} == 0 )); then
  echo "Nothing started." >&2
  exit 1
fi

echo
echo "▸ Following ${#started[@]} investigation(s)"

for id in "${started[@]}"; do
  for i in $(seq 1 72); do
    detail=$(curl -sS --max-time 20 -H "X-API-Key: ${API_KEY}" \
      "${BASE_URL}/v1/incidents/${id}" 2>/dev/null)
    status=$(printf '%s' "$detail" | sed -n 's/.*"status"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    printf '\r  %s  %-20s %ds ' "$id" "${status:-?}" $(( i * 5 ))

    case "$status" in
      completed|awaiting_approval|failed)
        severity=$(printf '%s' "$detail" | sed -n 's/.*"severity"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
        verdict=$(printf '%s' "$detail" | sed -n 's/.*"verdict"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
        printf '\r  %s  %-20s %s / %s\n' "$id" "$status" "${verdict:-?}" "${severity:-?}"
        break
        ;;
    esac
    sleep 5
    if (( i == 72 )); then printf '\r  %s  still running after 6 minutes\n' "$id"; fi
  done
done

echo
echo "Dashboard: ${BASE_URL}/ui"
echo
echo "Anything sitting in 'awaiting_approval' is the human-in-the-loop gate working."
echo "Approve it from Slack, the dashboard, or:"
echo "  curl -X POST ${BASE_URL}/v1/incidents/<id>/approve \\"
echo "    -H \"X-API-Key: \$API_KEY\" -H 'Content-Type: application/json' \\"
echo "    -d '{\"approved_all\": true, \"approver\": \"demo\"}'"
