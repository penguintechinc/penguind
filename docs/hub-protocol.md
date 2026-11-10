# penguind ↔ hub-api Sync Protocol (v1)

Contract: `services/hub-api/openapi/v1.yaml` (`/api/v1/agent/*`).

## Response Envelope

All JSON responses: `{status: success|error, data, meta: {version, timestamp, trace_id}}` (`backend.md`). Unwrapped: module binary (`application/wasm`), 302 redirect, 304 Not Modified. ETag applies to the canonical `data` payload.

## Identity & Enrollment

```
admin: pdcli hub bootstrap create --group G  → one-time token (shown once, hub stores hash)
agent: POST /api/v1/agent/enroll  (Bearer <bootstrap>)  → {agent_id, access_token ≤1h, refresh_token}
agent: POST /api/v1/agent/token   (refresh_token)       → new pair; old refresh token dead
```

| Mechanism | When | Notes |
|---|---|---|
| SPIFFE mTLS (X.509-SVID) | SPIRE deployed; XFCC from a trusted ingress only | `spiffe://penguintech.io/<env>/penguind/<agent_id>`; preferred |
| Machine JWT (bearer) | no SPIRE | `sub`=agent_id, `tenant`, scopes `hub:agent:sync`, `hub:agent:report` |

- mTLS trust: the ingress must overwrite XFCC (Envoy `forward_client_cert_details: SANITIZE_SET`). The hub accepts one element with one `spiffe://` URI, only from a peer in `HUB_TRUSTED_PROXY_CIDRS` with `HUB_TRUST_FORWARDED_CERT=1`, and only when the URI exactly matches a registered agent (`POST /api/v1/agents`). Agent ids are never taken from paths.
- Bootstrap token: single use, TTL ≤7d, consumed atomically; reuse → 401
- Refresh reuse → whole chain revoked (compromise signal); agent must re-enroll
- Tokens in OS keychain/secret store only, never plaintext files

## Poll Loop

```
every poll_interval_s (default 300) ± 10% jitter:
  GET /api/v1/agent/sync  If-None-Match: <last applied ETag>
    304 → nothing to do; refresh last_contact
    200 → verify + apply bundle → POST /api/v1/agent/status {applied_etag, result, modules}
    401 → refresh token once; still 401 → back off, keep cached state
    410 → agent revoked: stop syncing, unload hub-delivered modules, require re-enroll
    429/5xx/network → exponential backoff (cap = poll_interval_s), keep cached state
```

- ETag = sha256 of canonical bundle JSON (strong); changes on any policy, flag, membership or module change
- First poll after start: immediate, then jittered

## Module Delivery

1. Bundle `modules[]` is `ModuleManifest {id, version, sha256, signature, binary_url}`, identical to the existing GitHub fetcher shape
2. Agent downloads `binary_url` (200 body or 302 → presigned S3 URL, ≤5 min)
3. Agent recomputes sha256 and verifies minisign signature over
   `penguin-wasm-module/v1\nid=<id>\nversion=<version>\nsha256=<sha256>\n` against its **local trusted pubkey(s)**
4. Any mismatch → reject that module, keep previous version, report `loaded=false, error_code`
5. Hub never signs; a compromised hub can withhold or roll back, never inject code
6. Yanked versions disappear from the bundle; agent unloads them on next apply

Rollback protection: agent refuses a version lower than the highest it has verified for the same id unless the bundle drops the id entirely (then unload).

## Effective Config & Limits Clamp

```
group_merge = fold(groups):
  allowed_tools = ∩ (null = unrestricted)
  limits.*      = min
  settings      = per-key, last-write by group public_id order (deterministic)
hub_policy  = agent_override ?? group_merge        (per field)
effective   = clamp(hub_policy, license)
  allowed_tools = hub ∩ license_tools
  limits.*      = min(hub, license/compiled ceiling)
  flags[k]      = license[k] && hub[k]   (missing hub key = true; hub can never grant)
```

- Override wins over group merge, **never over license**
- Hub computes `policy`; agent re-applies the clamp locally (defence in depth — never trusts hub to grant)

## Offline Cache

| Item | Stored | On hub unreachable |
|---|---|---|
| Last bundle + ETag | agent state dir (integrity-checked) | keep applying |
| Verified module binaries | content-addressed by sha256 | keep loaded |
| Tokens | OS keychain | refresh when reachable |

- Age > `max_stale_s` (bundle-provided; default TBD — open question) → fall back to restrictive state: hub-delivered modules stay loaded only if `<module>` is license-entitled; config reverts to license defaults; status surfaced in tray/CLI as "hub stale since <ts>"
- Never-seen flags default OFF; cached flags last-known
- Restart with no cache and no hub → license defaults only, no hub modules

## Telemetry

Agent and hub emit OTel logs/metrics/traces: `hub.sync.requests{result=200|304|4xx|5xx}`, `hub.sync.latency` histogram, `hub.module.verify{ok|fail}`. Agent/tenant ids as UUIDs only.
