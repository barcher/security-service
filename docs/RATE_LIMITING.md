# Rate limiting on `/v1/dek/unwrap`

Per proposal threat T12 (oracle abuse), `/v1/dek/unwrap` is the most attractive endpoint
for an adversary who has gained partial access to a client cert: it returns plaintext DEK
material in response to wrapped input. A repeated flood of failed unwraps is the strongest
single signal of an unwrap-oracle attack. The security service rate-limits this endpoint
per-subject; over-cap calls are rejected with HTTP 429 and a `RATE_LIMIT_EXCEEDED` audit
event.

## Token-bucket semantics

The limiter is a per-subject-DN token bucket:

- Each subject gets its own bucket initialised to `capacity` tokens.
- Each successful unwrap consumes 1 token.
- The bucket refills at `refillTokensPerSecond` tokens per second, capped at `capacity`.
- An over-cap call returns 429; no token is consumed.
- Refill is lazy — buckets only update on the next call from that subject, so long-idle
  subjects refill all the way to capacity on their next request without a background timer.

Source:
[`adapters/inbound/http/.../ratelimit/PerSubjectRateLimiter.kt`](../adapters/inbound/http/src/main/kotlin/com/workautomations/security/adapters/inbound/http/ratelimit/PerSubjectRateLimiter.kt).

## Configuration

Loaded at startup by `RateLimitConfig.fromEnv()`:

| Env var | Default | Effect |
|---------|---------|--------|
| `SECURITY_UNWRAP_RATE_LIMIT_ENABLED` | `true` | `false` bypasses the limiter entirely (no 429s, no audit on overflow). Accepts `true`/`false`/`1`/`0`/`yes`/`no`/`on`/`off`, case-insensitive. **Never disable in prod.** |
| `SECURITY_UNWRAP_RATE_LIMIT_CAPACITY` | `5` | Token-bucket capacity per subject DN. Must be > 0 when enabled. |
| `SECURITY_UNWRAP_RATE_LIMIT_REFILL_PER_SECOND` | `1.0` | Refill rate in tokens / second. Must be > 0 when enabled. |

Parse failures (non-numeric values, zero or negative capacity / refill) raise
`RateLimitConfigException` at startup — misconfig surfaces immediately, not at first
traffic. The resolved config is logged at startup so an operator can confirm overrides
took effect.

### Picking values

The defaults (5 capacity, 1 token/s) target a single-instance deployment serving a single
monolith. They allow short bursts (up to 5 unwraps in a tight loop) while bounding the
steady-state rate at 1/s per subject.

For higher-throughput deployments:

- A single monolith instance unwrapping under load might need capacity 50 + 10/s.
- A separately-authenticated background backfill job (a distinct subject DN) gets its own
  bucket, so high backfill throughput doesn't starve interactive traffic.

For prod, tune by measuring the legitimate rate first; then set capacity to ~3× steady
state and refill to ~1.2× steady state. That gives headroom for bursts without inflating
the oracle-abuse blast radius.

## Operator note: local-process scope (Stream B)

The limiter holds bucket state in a per-process `ConcurrentHashMap`. **It is not shared
across replicas.** When the security service runs as a single instance, the configured
limit is the effective limit. When horizontally scaled to N replicas behind a load
balancer:

- A subject's effective limit becomes `capacity × N` per burst and `refillTokensPerSecond × N`
  per second, distributed unevenly across replicas based on load-balancer routing.
- A single adversary cycling through replicas can extract N× the per-replica limit.

This is acceptable for Stream B because the deployment posture is single-instance during
the cutover. Stream C (`SKS-C06..C08`) introduces the persistent audit chain and lays the
groundwork for a shared limiter backed by the security service's own MySQL — at that
point the limit becomes truly per-subject, regardless of replica count.

Until then, when scaling beyond one replica, divide the per-replica `CAPACITY` and
`REFILL_PER_SECOND` by replica count to keep the aggregate limit stable.

## Audit events produced

| Event type | Fires when | Detail |
|------------|------------|--------|
| `RATE_LIMIT_EXCEEDED` | A subject's bucket is empty when an unwrap arrives. | `detailJson` carries the endpoint path (`/v1/dek/unwrap`). |

The audit event is always emitted before the 429 response is sent, even when the limiter
is the SLF4J fallback (Stream B). The Stream-C `ExposedAuditLogRepository` writes the same
event into the HMAC-chained `audit_events` table.
