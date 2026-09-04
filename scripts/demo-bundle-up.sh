#!/usr/bin/env bash
# Start demo stack from a release bundle (registry images, no build).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose -f "${ROOT}/docker-compose.yml")
else
  COMPOSE=(docker compose -f "${ROOT}/docker-compose.yml")
fi

echo "==> starting demo stack (bundle / registry images)"
"${COMPOSE[@]}" up -d

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
echo "  docker-compose down -v"
