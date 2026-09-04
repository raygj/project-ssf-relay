# ssf-relay demo bundle

Standalone demo artifacts for a tagged release — **not** the full relay source tree.

## Contents

| Path | Purpose |
|------|---------|
| `docker-compose.yml` | Vault + trust-receiver + ssf-relay (pre-built images) |
| `ssf-relay.demo.yaml` | Minimal inbound Vault sink config |
| `demo/` | Trust-receiver config, sample SET, image pins |
| `scripts/demo-trigger.sh` | Inject compromised signal + verify revoke-self |
| `scripts/demo-up.sh` | Start stack + run trigger |

## Quick start

```bash
tar -xzf demo-bundle-v0.1.0-demo.tar.gz
cd ssf-relay-demo

# Set registry images if not using home-lab defaults (see demo/PIN.md)
export TRUST_RECEIVER_IMAGE=your-registry/ssf/trust-receiver:tag
export SSF_RELAY_IMAGE=your-registry/ssf/relay:tag

./scripts/demo-up.sh
```

Tear down:

```bash
docker-compose down -v
```

## Trigger only (existing stack)

```bash
RECEIVER_URL=http://localhost:9090 \
VAULT_ADDR=http://localhost:8200 \
VAULT_TOKEN=root \
./scripts/demo-trigger.sh
```

## Full source checkout

To build from source instead of pulling images, clone the full repo and use `make demo` (builds from `../ssf-trust-receiver` + local Dockerfile).
