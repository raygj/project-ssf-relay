#!/usr/bin/env bash
# Bring up the local demo stack and run the compromised → revoke-self loop.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose -f "${ROOT}/docker-compose.demo.yml")
else
  COMPOSE=(docker compose -f "${ROOT}/docker-compose.demo.yml")
fi

if [[ ! -d "${TRUST_RECEIVER_CONTEXT:-${ROOT}/../ssf-trust-receiver}" ]] && [[ -z "${TRUST_RECEIVER_IMAGE:-}" ]]; then
  echo "missing ../ssf-trust-receiver checkout and TRUST_RECEIVER_IMAGE unset" >&2
  echo "clone github.com/raygj/ssf-trust-receiver alongside this repo, or see demo/PIN.md" >&2
  exit 1
fi

echo "==> starting demo stack"
"${COMPOSE[@]}" up -d --build

echo "==> waiting for trust-receiver"
for _ in $(seq 1 30); do
  if curl -sf "${RECEIVER_URL:-http://localhost:9090}/healthz" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

echo "==> waiting for ssf-relay SSE subscription (5s)"
sleep 5

"${ROOT}/scripts/demo-trigger.sh"

echo
echo "Demo stack still running. Tear down with:"
echo "  docker-compose -f docker-compose.demo.yml down -v"
