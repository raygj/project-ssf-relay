#!/usr/bin/env bash
# Inject a source-compromised SET and verify ssf-relay revoked the Vault token.
set -euo pipefail

RECEIVER_URL="${RECEIVER_URL:-http://localhost:9090}"
VAULT_ADDR="${VAULT_ADDR:-http://localhost:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-root}"
SET_FILE="${SET_FILE:-$(dirname "$0")/../demo/source-compromised.set.json}"

echo "==> receiver: ${RECEIVER_URL}"
echo "==> vault:    ${VAULT_ADDR}"

echo "==> checking Vault token before trigger"
before_code=$(curl -s -o /dev/null -w '%{http_code}' \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  "${VAULT_ADDR}/v1/auth/token/lookup-self")
if [[ "${before_code}" != "200" ]]; then
  echo "expected token lookup 200 before trigger, got ${before_code}" >&2
  exit 1
fi

echo "==> posting source-compromised SET to trust receiver"
curl -sf -X POST "${RECEIVER_URL}/" \
  -H "Content-Type: application/json" \
  --data-binary "@${SET_FILE}" >/dev/null

echo "==> waiting for relay to act (revoke-self)"
for _ in $(seq 1 15); do
  after_code=$(curl -s -o /dev/null -w '%{http_code}' \
    -H "X-Vault-Token: ${VAULT_TOKEN}" \
    "${VAULT_ADDR}/v1/auth/token/lookup-self" || true)
  if [[ "${after_code}" == "403" ]]; then
    echo "✓ loop closed — Vault token revoked (lookup-self → 403)"
    exit 0
  fi
  sleep 1
done

echo "token still valid after trigger (lookup-self → ${after_code:-unknown})" >&2
echo "check ssf-relay logs: docker-compose -f docker-compose.demo.yml logs ssf-relay" >&2
exit 1
