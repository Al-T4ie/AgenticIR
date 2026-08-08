#!/usr/bin/env bash
# End-to-end probe of a running AgenticIR deployment.
#
#   BASE_URL=https://app.example.com API_KEY=... bash infra/scripts/smoke-test.sh
#
# Checks liveness, readiness, auth enforcement, and (with --full) drives one
# real investigation through the API.

set -uo pipefail

BASE_URL="${BASE_URL:-http://localhost:8000}"
API_KEY="${API_KEY:-}"
FULL=false
[[ "${1:-}" == "--full" ]] && FULL=true

BASE_URL="${BASE_URL%/}"
pass=0
fail=0

check() {
  local name="$1" expected="$2" actual="$3"
  if [[ "$actual" == "$expected" ]]; then
    echo "  ✓ ${name}"
    (( pass++ ))
  else
    echo "  ✗ ${name} — expected ${expected}, got ${actual}"
    (( fail++ ))
  fi
}

code() { curl -sS -o /dev/null -w '%{http_code}' --max-time 20 "$@" 2>/dev/null || echo 000; }

echo "▸ Probing ${BASE_URL}"

check "GET /health returns 200"                 200 "$(code "${BASE_URL}/health")"
check "GET /ready returns 200"                  200 "$(code "${BASE_URL}/ready")"
check "GET /docs returns 200"                   200 "$(code "${BASE_URL}/docs")"
check "GET /ui redirects to login"              303 "$(code "${BASE_URL}/ui")"
check "GET /v1/incidents without key is 401"    401 "$(code "${BASE_URL}/v1/incidents")"
check "GET /v1/incidents with bad key is 401"   401 "$(code -H 'X-API-Key: wrong' "${BASE_URL}/v1/incidents")"
check "POST /webhooks/alert unauthenticated"    401 "$(code -X POST -H 'Content-Type: application/json' -d '{}' "${BASE_URL}/webhooks/alert")"
check "POST /slack/events unsigned is 401"      401 "$(code -X POST -H 'Content-Type: application/json' -d '{}' "${BASE_URL}/slack/events")"

if [[ -n "$API_KEY" ]]; then
  check "GET /v1/incidents with key is 200"     200 "$(code -H "X-API-Key: ${API_KEY}" "${BASE_URL}/v1/incidents")"
  check "POST /v1/incidents empty body is 422"  422 "$(code -X POST -H "X-API-Key: ${API_KEY}" -H 'Content-Type: application/json' -d '{}' "${BASE_URL}/v1/incidents")"
else
  echo "  · API_KEY unset — skipping authenticated checks"
fi

if $FULL; then
  if [[ -z "$API_KEY" ]]; then
    echo "  ✗ --full needs API_KEY"
    (( fail++ ))
  else
    echo "▸ Running one real investigation (this costs LLM tokens)"
    body=$(curl -sS --max-time 30 -X POST "${BASE_URL}/v1/incidents" \
      -H "X-API-Key: ${API_KEY}" -H 'Content-Type: application/json' \
      -d '{"source":"smoke-test","alert":{"title":"Smoke test: outbound beacon","severity":"medium","src_ip":"10.4.2.19","dst_ip":"198.51.100.77","detail":"Repeating 60s HTTPS callouts from FIN-WS-04."}}' 2>/dev/null)

    incident_id=$(printf '%s' "$body" | sed -n 's/.*"incident_id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    if [[ -z "$incident_id" ]]; then
      echo "  ✗ investigation did not start: ${body:0:300}"
      (( fail++ ))
    else
      echo "  ✓ started ${incident_id}"
      for i in $(seq 1 60); do
        sleep 5
        detail=$(curl -sS --max-time 20 -H "X-API-Key: ${API_KEY}" \
          "${BASE_URL}/v1/incidents/${incident_id}" 2>/dev/null)
        status=$(printf '%s' "$detail" | sed -n 's/.*"status"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
        printf '\r    status: %-20s (%ds)' "${status:-?}" $(( i * 5 ))
        case "$status" in
          completed|awaiting_approval)
            echo; echo "  ✓ reached '${status}'"; (( pass++ )); break ;;
          failed)
            echo; echo "  ✗ investigation failed"; (( fail++ )); break ;;
        esac
        if (( i == 60 )); then
          echo; echo "  ✗ still '${status}' after 5 minutes"; (( fail++ ))
        fi
      done
    fi
  fi
fi

echo
echo "── ${pass} passed, ${fail} failed ──"
exit $(( fail > 0 ? 1 : 0 ))
