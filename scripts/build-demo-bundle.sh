#!/usr/bin/env bash
# Pack demo-only files into dist/demo-bundle-<tag>.tar.gz for release assets.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TAG="${1:-$(git -C "${ROOT}" describe --tags --exact-match 2>/dev/null || git -C "${ROOT}" describe --tags --always --dirty)}"

DIST="${ROOT}/dist"
STAGING="$(mktemp -d)"
BUNDLE="ssf-relay-demo"

cleanup() { rm -rf "${STAGING}"; }
trap cleanup EXIT

mkdir -p "${DIST}" "${STAGING}/${BUNDLE}/demo" "${STAGING}/${BUNDLE}/scripts"

cp "${ROOT}/demo/BUNDLE-README.md" "${STAGING}/${BUNDLE}/README.md"
cp "${ROOT}/docker-compose.demo.bundle.yml" "${STAGING}/${BUNDLE}/docker-compose.yml"
cp "${ROOT}/ssf-relay.demo.yaml" "${STAGING}/${BUNDLE}/"
cp "${ROOT}/demo/PIN.md" "${ROOT}/demo/trust-receiver.yaml" "${ROOT}/demo/source-compromised.set.json" \
   "${STAGING}/${BUNDLE}/demo/"
cp "${ROOT}/scripts/demo-trigger.sh" "${STAGING}/${BUNDLE}/scripts/"
cp "${ROOT}/scripts/demo-bundle-up.sh" "${STAGING}/${BUNDLE}/scripts/demo-up.sh"
chmod +x "${STAGING}/${BUNDLE}/scripts/"*.sh

OUT="${DIST}/demo-bundle-${TAG}.tar.gz"
tar -czf "${OUT}" -C "${STAGING}" "${BUNDLE}"
echo "wrote ${OUT}"
tar -tzf "${OUT}"
