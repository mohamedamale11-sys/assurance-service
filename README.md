# Assurance Service

A small, standalone security-assurance service that accepts signed events, stores
an append-only audit log, and exposes verifiable evidence (hash chain + Merkle
roots). It also provides a policy-as-code decision API and privacy-preserving
aggregates.

## Why this exists (plain English)

This service is the "independent verifier" for your system. The backend sends
important events (trades, policy decisions, swaps, etc.) to the verifier. The
verifier writes each event into a tamper-evident log. Later, anyone can call
`/audit/verify` to prove the log was not modified.

If a record is changed or deleted, verification fails. That is the assurance.

## Architecture overview

1) Client/backend sends a signed JSON event to `POST /events`.
2) The service verifies the HMAC signature.
3) The event is appended to an immutable hash chain (`events.log`).
4) Every batch, a Merkle root is written to `roots.log`.
5) `/audit/verify` recomputes the chain and roots to detect tampering.

## Key security guarantees

- Tamper evidence: any log edit/deletion/reorder is detectable.
- Provenance: only a trusted emitter (shared secret) can submit events.
- Auditability: verification can be repeated offline with the CLI.

## Quick start

```bash
cd assurance-service
ASSURE_SHARED_SECRET=dev_secret go run ./cmd/assure-server
```

Health check:

```bash
curl -s http://127.0.0.1:9010/health
```

## Send a signed event (HMAC)

```bash
body='{"type":"policy.decision","source":"demo","timestamp":"2025-01-01T00:00:00Z","payload":{"user":"u1","action":"swap.execute","allow":true}}'
sig=$(printf '%s' "$body" | openssl dgst -sha256 -hmac "dev_secret" | sed 's/^.* //')

curl -s -X POST http://127.0.0.1:9010/events \
  -H "Content-Type: application/json" \
  -H "X-Assurance-Signature: sha256=$sig" \
  -d "$body"
```

## Verify the audit log

```bash
curl -s http://127.0.0.1:9010/audit/verify
curl -s http://127.0.0.1:9010/audit/root/latest
curl -s "http://127.0.0.1:9010/audit/events?limit=5"
```

## API endpoints

- `GET /health`
- `POST /events` (HMAC signed)
- `GET /audit/root/latest`
- `GET /audit/verify`
- `GET /audit/events?limit=100`
- `POST /policy/check`
- `GET /privacy/tokens?window_hours=24&k=5&epsilon=0.7&seed=0`

## Event format

Minimal example:

```json
{
  "id": "optional",
  "type": "policy.decision",
  "source": "api",
  "timestamp": "2025-01-01T00:00:00Z",
  "payload": {
    "user": "u1",
    "action": "swap.execute",
    "allow": true
  }
}
```

If `id` is not provided, the service computes a stable hash of the event.

## HMAC signing details

The service expects:

```
X-Assurance-Signature: sha256=<hex>
```

Where `<hex>` is HMAC-SHA256 of the raw request body using
`ASSURE_SHARED_SECRET`.

## Policy engine

Rules are defined in `policies/policy.json`. Example input:

```bash
curl -s -X POST http://127.0.0.1:9010/policy/check \
  -H "Content-Type: application/json" \
  -d '{"subject":{"id":"u1","roles":["user"],"attributes":{"tier":"free"}},"action":"wallet.send","resource":"wallet","context":{"amount_sol":0.5}}'
```

The engine evaluates rules top-down and returns allow/deny with reasons.

## Privacy aggregates

`GET /privacy/tokens` computes k-anon + differential privacy summaries
from the event log. If the count is below k, results are suppressed.

## CLI verification (offline)

```bash
go run ./cmd/assurectl verify --data ./data --batch 100
```

## Data storage

By default the service writes:

- `data/events.log` (append-only record chain)
- `data/roots.log` (Merkle roots per batch)

These files are the evidence artifacts for audits.

## Environment variables

- `ASSURE_PORT` (default 9010)
- `ASSURE_DATA_DIR` (default ./data)
- `ASSURE_SHARED_SECRET` (required for signatures)
- `ASSURE_BATCH_SIZE` (default 100)
- `ASSURE_K_ANON` (default 5)
- `ASSURE_DP_EPS` (default 0.7)
- `ASSURE_DP_SEED` (default 0)

## Integration with the Go backend

Set these in your backend `.env`:

```
ASSURANCE_URL=http://127.0.0.1:9010
ASSURANCE_SHARED_SECRET=dev_secret
```

The backend signs events and posts to `/events`. It exposes `/assurance/status`
so the UI can show a Verified/Unverified badge.

## Troubleshooting

- `503 assurance unavailable` from the backend means `ASSURANCE_URL` is empty or
  the assurance service is not running.
- `401 invalid signature` from assurance means `ASSURE_SHARED_SECRET` does not
  match the backend's `ASSURANCE_SHARED_SECRET`.
- If verification fails, inspect `events.log` and `roots.log` for corruption.

## License

MIT
