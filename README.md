# ssf-relay

**The relay is a pattern, not a tool.**

A signal arrives from the trust fabric. The relay receives it and fans out to every local system that needs to respond — Vault revokes the token, Kubernetes cordons the node, OPA injects a deny policy, a webhook fires to the SIEM. One signal. Parallel local consequences. No custom webhook contracts. No bilateral schema negotiation. The SSF taxonomy is the contract.

The outbound path is the same pattern in reverse: tail structured logs, parse, emit SETs. The relay is the edge adapter that closes the loop between the fabric and the system.

---

A generic, source-pluggable binary that tails structured infrastructure logs and emits SSF SETs (RFC 8417 Security Event Tokens) to a trust receiver — and subscribes to that receiver to translate inbound CAEP signals into local system actions.

Sources and sinks are loosely coupled to the core via two-method interfaces. The relay is not Vault-specific, not k8s-specific, not OPA-specific. Every new system is one adapter file and a blank import.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Per-system edge (ssf-relay)                             │
│                                                          │
│  [local logs] ──► [source parser] ──► SET out           │
│                                                          │
│  SET in ──► [subscriber] ──► [router] ──► [adapters]    │
│                                          vault / k8s /   │
│                                          opa / webhook   │
└──────────────────────────┬──────────────────────────────┘
                           │ SSF/CAEP
                           ▼
┌─────────────────────────────────────────────────────────┐
│  Central fabric (ssf-trust-receiver)                     │
│  validate → trust ring → reactor → CAEP delivery        │
└─────────────────────────────────────────────────────────┘
```

The router is a diverge/converge fan-out: one inbound signal dispatches to all registered adapters in parallel. All adapters run even if one errors. New systems join by registering an adapter — the router and subscriber are unaware of them until registration.

---

## Quick Start

```bash
# Build
make build

# Run
./bin/ssf-relay ssf-relay.yaml
```

Example config: [`ssf-relay.yaml`](ssf-relay.yaml)

---

## Demo (inbound loop)

Reproduces the ship story: **trust receiver → SSE → ssf-relay → Vault `revoke-self`**.

```bash
# Local stack (Vault dev + real ssf-trust-receiver + ssf-relay)
# Requires ../ssf-trust-receiver cloned alongside this repo — see demo/PIN.md
make demo

# Tear down
make demo-down

# Trigger only (cluster or already-running stack)
RECEIVER_URL=http://localhost:9090 \
VAULT_ADDR=http://localhost:8200 \
VAULT_TOKEN=root \
make demo-trigger
```

Minimal sink config: [`ssf-relay.demo.yaml`](ssf-relay.demo.yaml)  
Compose stack: [`docker-compose.demo.yml`](docker-compose.demo.yml)


Medium: [Response, Not Reactivity — Closing the Security Loop at Machine Speed](https://medium.com/@ray.jim/response-not-reactivity-closing-the-security-loop-at-machine-speed-c6b9e3a7304c)

---

## Config Reference

```yaml
ssf:
  receiver_url: http://localhost:9000/   # SSF receiver (outbound target + inbound SSE source)
  issuer: ssf-relay                      # SET iss claim
  timeout_secs: 5                        # HTTP POST timeout

sources:                                 # outbound: log → SET
  - name: my-source
    type: vault-audit
    path: /path/to/audit.log
    config: ...

sinks:                                   # inbound: CAEP signal → local action
  - event_type: https://schemas.openid.net/secevent/caep/event-type/source-compromised
    action: vault
    config:
      vault_addr: http://vault:8200
      vault_token_env: VAULT_TOKEN
```

---

## Source Types

| Type | Log format | Event URIs emitted |
|------|-----------|-------------------|
| `vault-audit` | Vault audit JSON | `vault/credential-issued`, `vault/secret-accessed`, `vault/credential-revoked`, `vault/secret-denied`, `vault/auth-event` |
| `k8s-audit` | Kubernetes `audit.k8s.io/v1` JSON | `relay/k8s/secret-accessed`, `relay/k8s/secret-denied`, `relay/k8s/credential-issued`, `relay/k8s/credential-revoked` |
| `opa-decision` | OPA decision log JSON | `relay/opa/policy-denied`, `relay/opa/policy-allowed` |

All event URI bases are `https://schemas.fiam/`.

---

## Source Config

### vault-audit

```yaml
config:
  mount_rules:
    - prefix: database/creds/     # path prefix to match
      engine: database             # populates secret_engine metadata
      event: https://schemas.fiam/vault/credential-issued
  drop_prefixes:
    - sys/
    - auth/token/lookup
```

Classification order: revoke check → drop prefixes → error → auth login → mount rules → drop.

### k8s-audit

```yaml
config:
  stages: [ResponseComplete]       # audit stages to process
  drop_users:
    - system:node
  drop_verbs: [watch, list]
```

### opa-decision

```yaml
config:
  emit_allow: false    # emit SETs for allowed decisions? (default false)
  drop_paths:
    - data.system.main
```

---

## Sink Types

| Action | Trigger | Effect |
|--------|---------|--------|
| `vault` | source-compromised | `POST /v1/auth/token/revoke-self` — kills the relay's Vault session |
| `vault` | source-degraded | `POST /v1/identity/entity/id/{id}` — sets `ssf_status=degraded` metadata |
| `vault` | source-recovered | Clears `ssf_status` metadata |
| `k8s-cordon` | source-compromised / source-degraded | `PATCH /api/v1/nodes/{name}` → `unschedulable: true` |
| `k8s-cordon` | source-recovered | `PATCH /api/v1/nodes/{name}` → `unschedulable: false` |
| `opa-policy` | source-compromised | `PUT /v1/policies/{id}` — injects deny-all Rego policy |
| `opa-policy` | source-degraded | `PUT /v1/policies/{id}` — injects warning/restrict Rego policy |
| `opa-policy` | source-recovered | `DELETE /v1/policies/{id}` — removes injected policies |
| `webhook` | any | `POST` the full inbound SET as JSON to a configured URL |

---

## Adding a New Source

1. Create a package under `sources/<yourname>/source.go`.
2. Implement the `relay.Source` interface:

```go
type Source interface {
    Name() string
    Parse(line string) (relay.Event, bool)
}
```

3. Register in `init()`:

```go
func init() {
    sources.Register("my-source-type", func(cfg map[string]interface{}) (relay.Source, error) {
        return NewSource(cfg)
    })
}
```

4. Add a blank import in `cmd/ssf-relay/main.go`.
5. Add a source block to your config YAML.

## Adding a New Sink

1. Create a package under `actions/<yourname>/adapter.go`.
2. Implement the `relay.ActionAdapter` interface:

```go
type ActionAdapter interface {
    Name() string
    EventTypes() []string
    Act(ctx context.Context, set InboundSET) error
}
```

3. Register in `init()`:

```go
func init() {
    actions.Register("my-action", func(cfg map[string]interface{}) (relay.ActionAdapter, error) {
        return NewAdapter(cfg)
    })
}
```

4. Add a blank import in `cmd/ssf-relay/main.go`.
5. Add a sink block to your config YAML.

The core (`relay` package) never imports `sources/` or `actions/` — dependency flows one way. The router fans out to all registered adapters for a given event type; multiple adapters per event type are supported and expected.

---

## Wire Format (SET)

```json
{
  "iss": "ssf-relay",
  "iat": 1700000000,
  "jti": "set-<uuid>",
  "correlation_id": "<source request ID>",
  "source": "<source name from config>",
  "events": {
    "https://schemas.fiam/vault/credential-issued": {
      "entity_id": "...",
      "entity_name": "...",
      "accessor": "...",
      "secret_path": "...",
      "secret_engine": "...",
      "lease_id": "...",
      "ttl_seconds": "3600"
    }
  }
}
```

Compatible with `ssf-trust-receiver` at `github.com/raygj/ssf-trust-receiver`.
