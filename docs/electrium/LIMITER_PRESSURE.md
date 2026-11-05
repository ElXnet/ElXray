# Limiter pressure metrics

Each ElXray subscription has independent upload and download `Budget` instances. `Budget.Pressure()` exposes four local observation fields:

| Field | Meaning |
| --- | --- |
| `PayloadBytes` | Cumulative dispatcher payload bytes (existing counter) |
| `BlockedCalls` | Number of `WaitN` invocations that actually waited for rate tokens |
| `BlockedNanos` | Sum of actual time those invocations spent blocked, including canceled waits |
| `ActiveWaiters` | Current count of rate-limited `WaitN` invocations |

All counters are atomic and do not reset when a speed policy changes; **the core incarnation changes on restart**. Across fields, the snapshot is not transactional. The core does not count an invalid wait, an idle connection, a disabled subscription or a nonblocking allowed debit as saturation. A waiter woken many times by a policy update is counted only once until that call finishes.

## Contract for Control

These counters are **local instrumentation only**. They have not yet been added to the signed accounting evidence or mTLS transport. Never trust a client-provided claim of `BlockedCalls`, infer a physical device from it, or use the aggregate numbers as a direct right to raise a grant.

A future signed demand report must bind the exact subscription, target node/resource, core incarnation, monotonic sequence, policy revision and a fresh Control challenge. Control should compare counter deltas within one incarnation, combine observed throughput with wait pressure and assign user caps/weights from its own database. Inactive, unknown, reordered or stale sources must freeze their existing rate commitment.

The existing token buckets, retransmission/payload accounting and rate barrier/lease enforcement are unchanged by this instrumentation. Test with `go test -race ./common/subscriptionrate` before linking into the remote telemetry protocol.
