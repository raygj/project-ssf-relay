# Demo dependency pins

Local `docker-compose.demo.yml` builds **ssf-trust-receiver** from a sibling checkout:

```
../ssf-trust-receiver   →  github.com/raygj/ssf-trust-receiver
```

Home-lab cluster images (verified 2026-06-28):

| Component | Image |
|-----------|-------|
| ssf-trust-receiver | `ghcr.io/example/ssf/ssf/trust-receiver:dev` |
| ssf-relay | `ghcr.io/example/ssf/ssf/relay:dev` |

To run the demo against the Talos cluster instead of compose:

```bash
RECEIVER_URL=http://localhost:9090 \
VAULT_ADDR=http://localhost:8200 \
VAULT_TOKEN=root \
./scripts/demo-trigger.sh
```

## Release demo bundle

Tagged releases attach `demo-bundle-<tag>.tar.gz` — compose, configs, and trigger scripts **only** (pre-built images, no full repo). Build locally with `make demo-bundle VERSION=v0.1.0-demo`. See [`BUNDLE-README.md`](BUNDLE-README.md).
