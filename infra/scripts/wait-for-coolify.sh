#!/usr/bin/env bash
# Block until cloud-init has finished installing Coolify on the new server.
#
#   eval "$(terraform -chdir=infra/terraform output -raw bootstrap_env)"
#   bash infra/scripts/wait-for-coolify.sh
#
# Reads SERVER_IP (or the first argument). Exits non-zero if the bootstrap
# script reported a failure, printing the remote log tail so you can see why.

set -euo pipefail

IP="${1:-${SERVER_IP:-}}"
TIMEOUT="${TIMEOUT:-1200}"
SSH_USER="${SSH_USER:-root}"
SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o BatchMode=yes)

if [[ -z "$IP" ]]; then
  echo "usage: SERVER_IP=<ip> $0   (or: $0 <ip>)" >&2
  echo "hint:  eval \"\$(terraform -chdir=infra/terraform output -raw bootstrap_env)\"" >&2
  exit 2
fi

echo "▸ Waiting for SSH on ${IP}"
deadline=$(( $(date +%s) + TIMEOUT ))
until ssh "${SSH_OPTS[@]}" "${SSH_USER}@${IP}" true 2>/dev/null; do
  if (( $(date +%s) > deadline )); then
    echo "✗ SSH never became reachable within ${TIMEOUT}s." >&2
    echo "  Check that your current IP is inside admin_ips in terraform.tfvars." >&2
    exit 1
  fi
  printf '.'
  sleep 10
done
echo -e "\n  ✓ SSH is up"

echo "▸ Waiting for cloud-init to finish installing Coolify"
echo "  (follow along with: ssh ${SSH_USER}@${IP} tail -f /var/log/agenticir-bootstrap.log)"

while :; do
  if ssh "${SSH_OPTS[@]}" "${SSH_USER}@${IP}" \
      'test -f /var/lib/agenticir/bootstrap-failed' 2>/dev/null; then
    reason=$(ssh "${SSH_OPTS[@]}" "${SSH_USER}@${IP}" 'cat /var/lib/agenticir/bootstrap-failed' 2>/dev/null || echo unknown)
    echo -e "\n✗ Bootstrap failed on the server: ${reason}" >&2
    echo "── last 40 log lines ─────────────────────────────────────────" >&2
    ssh "${SSH_OPTS[@]}" "${SSH_USER}@${IP}" 'tail -40 /var/log/agenticir-bootstrap.log' >&2 || true
    exit 1
  fi

  if ssh "${SSH_OPTS[@]}" "${SSH_USER}@${IP}" \
      'test -f /var/lib/agenticir/bootstrap-complete' 2>/dev/null; then
    finished=$(ssh "${SSH_OPTS[@]}" "${SSH_USER}@${IP}" 'cat /var/lib/agenticir/bootstrap-complete' 2>/dev/null || true)
    echo -e "\n  ✓ Bootstrap completed at ${finished}"
    break
  fi

  if (( $(date +%s) > deadline )); then
    echo -e "\n✗ Bootstrap did not finish within ${TIMEOUT}s." >&2
    ssh "${SSH_OPTS[@]}" "${SSH_USER}@${IP}" 'tail -30 /var/log/agenticir-bootstrap.log' >&2 || true
    exit 1
  fi
  printf '.'
  sleep 15
done

echo "▸ Checking that Coolify answers on :8000"
for _ in $(seq 1 30); do
  if curl -fsS -o /dev/null --max-time 5 "http://${IP}:8000"; then
    echo "  ✓ Coolify dashboard is up"
    echo
    echo "Next: open http://${IP}:8000 and create the admin account."
    echo "      The first visitor claims the instance — do it now, before anyone else can."
    exit 0
  fi
  sleep 10
done

echo "! Coolify did not answer on http://${IP}:8000 from here." >&2
echo "  It may still be starting, or your IP may not be in admin_ips." >&2
exit 1
