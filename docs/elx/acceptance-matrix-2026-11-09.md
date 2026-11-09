# ElXray XR acceptance matrix — Stage 1

**Snapshot:** ElXray `main@8e4dbed76bef9755395945a4b7e2982d138ad62d`, Control `main@3e8891872f172eaeb92696c1527fd25ab158fa06`. **2026-11-09**.
**Source:** `05_ELXRAY_updated_2026-11-09.md`. This matrix enumerates all 56 numbered XR requirements; test references denote *planned acceptance coverage*, **not PASS**.

Legend: **CORE** = observed mechanism in code, not full acceptance; **PARTIAL** = portion implemented; **GAP** = required behavior not present in reviewed source; **VERIFY** = not validated and must not be advertised.

| XR | Source path / symbol in current code (or explicit missing owner) | State | Acceptance suite (NOT RUN to full target) | Stage(s) |
|---|---|---|---|---|
| XR-001 | `app/policy/subscription.go;app/dispatcher/rate.go` | PARTIAL | XR-T01,02,07 | 2,6,8,10 |
| XR-010 | `app/policy/manager.go;app/policy/lease.go` | PARTIAL | XR-T06,T13 | 2 |
| XR-011 | `app/policy/profile_fence.go;proxy/vless` | GAP | XR-T02,T12 | 4,6 |
| XR-012 | `app/policy/command/command.go` | GAP | XR-T06,T11 | 12 |
| XR-013 | `app/policy/manager.go` | GAP | XR-T06,T13 | 2,12 |
| XR-014 | `app/policy/runtime.go;app/policy/persistence.go` | PARTIAL | XR-T05,T11 | 3,4,12 |
| XR-015 | `app/policy/manager.go;app/policy/lease.go` | GAP | XR-T13 | 2 |
| XR-020 | `app/policy/command/command.go:checkLocalPeer` | PARTIAL | XR-T13 | 2 |
| XR-021 | `app/policy/command/command.proto:SubscriptionService` | CORE | XR-T06 | 1,2 |
| XR-022 | `app/policy/command/{command,lease,profile_fence,rate_barrier}.go` | PARTIAL | XR-T06,T11 | 2,3,4,6,7,12 |
| XR-023 | `app/policy/runtime.go:UpdateSubscription;app/policy/persistence.go` | GAP | XR-T05,T06 | 3 |
| XR-024 | `app/policy/persistence.go:DurablePolicyProof` | PARTIAL | XR-T05,T06 | 3,12 |
| XR-025 | `app/policy/lease.go:ControlLeaseTranscript;app/policy/command/command.proto` | PARTIAL | XR-T06,T14 | 1,3,5 |
| XR-026 | `app/policy/command/command.go:checkLocalPeer;app/policy/lease.go` | GAP | XR-T13 | 2 |
| XR-030 | `app/policy/persistence.go:savedPolicies` | PARTIAL | XR-T05 | 3 |
| XR-031 | `app/policy/runtime.go:UpdateSubscription;app/policy/persistence.go:write` | PARTIAL | XR-T05,T06 | 3 |
| XR-032 | `app/policy/persistence.go:policyStore.write` | PARTIAL | XR-T05 | 3 |
| XR-033 | `app/policy/persistence.go:restorePolicies` | PARTIAL | XR-T05,T08 | 3,11 |
| XR-034 | `app/policy/persistence.go:restorePolicies` | GAP | XR-T05,T14 | 3,7 |
| XR-035 | `app/policy/persistence.go:savedPolicies` | GAP | XR-T05 | 3 |
| XR-040 | `common/subscriptionrate/limits.go;app/policy/subscription.go` | PARTIAL | XR-T01,T09 | 8 |
| XR-041 | `common/subscriptionrate/limits.go` | GAP | XR-T01,T09 | 8 |
| XR-042 | `app/policy/command/command.go:SetSubscription` | PARTIAL | XR-T01,T13 | 2,8 |
| XR-043 | `app/dispatcher/rate.go` | PARTIAL | XR-T03,T15 | 8,10 |
| XR-044 | `app/policy/rate_barrier.go;common/subscriptionrate/limits.go` | PARTIAL | XR-T03 | 8 |
| XR-045 | `common/subscriptionrate/limits.go:burst` | PARTIAL | XR-T03,T08 | 3,8 |
| XR-046 | `app/policy/pressure.go;common/subscriptionrate/limits.go` | PARTIAL | XR-T01,T09 | 8 |
| XR-050 | `testing/subscriptionrate/{vision,vless,matrix}_test.go` | VERIFY | XR-T02 | 9 |
| XR-051 | `ElX-control/internal/elxcontrol/session/proof.go;core missing` | GAP | XR-T02,T12 | 5,6 |
| XR-052 | `app/policy/command/command.go;core missing` | GAP | XR-T02,T12 | 5,6 |
| XR-053 | `app/policy/profile_fence.go;core missing owner binding` | GAP | XR-T02,T04 | 6,7 |
| XR-054 | `ElX-control/internal/elxcontrol/session/reserve.go;core missing` | GAP | XR-T02,T09 | 6 |
| XR-055 | `ElX-control/internal/elxcontrol/session/proof.go;core missing` | GAP | XR-T02,T12 | 5,6 |
| XR-056 | `ElX-control/internal/elxcontrol/session/proof.go;ElX-client future` | GAP | XR-T12 | 5,6,12 |
| XR-057 | `core profile UUID tracking only;ElX-control/session` | GAP | XR-T12 | 5,6,12 |
| XR-058 | `app/dispatcher/rate.go;proxy/vless;flow proof absent` | GAP | XR-T02,T12 | 5,6 |
| XR-059 | `ElX-client future;core no HWID dependency intended` | VERIFY | XR-T12 | 5,12 |
| XR-060 | `common/sessionfence/registry.go;app/policy/profile_fence.go` | PARTIAL | XR-T04 | 7,9 |
| XR-061 | `common/sessionfence/registry.go:Track;app/policy/profile_fence.go:DrainVLESSProfile` | PARTIAL | XR-T04 | 7,9 |
| XR-062 | `app/policy/profile_fence.go:DrainVLESSProfile` | PARTIAL | XR-T04,T14 | 7 |
| XR-063 | `app/policy/rate_barrier.go:ProveRateBarrier` | PARTIAL | XR-T03 | 8 |
| XR-064 | `app/policy/profile_fence.go:DrainVLESSProfile` | GAP | XR-T14 | 7 |
| XR-070 | `app/policy/usage.go:SignedUsage` | PARTIAL | XR-T07 | 10 |
| XR-071 | `app/dispatcher/rate.go:rateReader,RateWriter` | PARTIAL | XR-T07,T15 | 10 |
| XR-072 | `app/policy/usage.go;period bins absent` | GAP | XR-T07,T15 | 10 |
| XR-073 | `app/policy/usage.go;app/policy/persistence.go` | GAP | XR-T07,T15 | 10 |
| XR-074 | `app/policy/pressure.go:SignedPressure` | PARTIAL | XR-T07 | 10 |
| XR-075 | `app/dispatcher/rate.go:RecordPayload` | VERIFY | XR-T15 | 10 |
| XR-080 | `app/policy/lease.go:RenewControlLease;common/subscriptionrate/limits.go` | PARTIAL | XR-T08,T13 | 2,11 |
| XR-081 | `app/policy/lease.go;freeze absent` | GAP | XR-T08,T09 | 11 |
| XR-082 | `app/policy/lease.go;entitlement calendar expiry absent` | PARTIAL | XR-T08 | 11 |
| XR-083 | `app/policy/command/command.go;health readback absent` | GAP | XR-T11 | 12 |
| XR-090 | `.github/workflows/upstream-sync.yml;go.mod` | PARTIAL | XR-T06,T10 | 14 |
| XR-091 | `go.mod;release workflows` | PARTIAL | XR-T10 | 12,14 |
| XR-092 | `app/policy/command/*.go;testing/subscriptionrate` | VERIFY | XR-T10,T13,T14 | 2,13 |
| XR-093 | `testing/subscriptionrate/bench_client.py;common/subscriptionrate` | VERIFY | XR-T10 | 13 |

## Test matrix (target, not green claims)

| Suite | Acceptance scope | Current evidence | Target stage |
|---|---|---|---|
| XR-T01 | parent+child sharing and direction B/s | partial existing local tests | 8,13 |
| XR-T02 | real Vision+XHTTP proof and payload | no admitted flow-binding coverage | 5,6,9,13 |
| XR-T03 | rate update/barrier, buffered writes | partial quiet-barrier tests | 8,13 |
| XR-T04 | all active/idle/racing owner flows fence | partial profile fence tests | 7,9,13 |
| XR-T05 | durability crash points, stale backups | partial JSON state tests | 3,13 |
| XR-T06 | idempotency, CAS, standalone, rejected auth | partial CAS only | 2,3,4,13 |
| XR-T07 | signed cumulative, period, pressure | partial signed telemetry | 10,13 |
| XR-T08 | separate current fail-closed and target freeze | current lease tests only | 11,13 |
| XR-T09 | two executors and exclusive owner with global budget | Control local tests, not full managed path | 6,8,12,13 |
| XR-T10 | race/fuzz/full tests/2GiB performance | partial current CI | 13 |
| XR-T11 | UI→Control→core→applied readback | not full target | 4,12,13 |
| XR-T12 | display metadata versus cryptographic identity | not full target | 5,6,12,13 |
| XR-T13 | untrusted local process and in-lease ceiling raise | not full target | 2,13 |
| XR-T14 | wrong binding signed fence, snapshot replay | not full target | 3,7,13 |
| XR-T15 | partial writes, UDP, reboot/period boundary | not full target | 10,13 |

## Version / migration gates

1. `go.mod`: core Go 1.27; module path `github.com/xtls/xray-core`. Consumer uses embedded `command.proto` equal blob SHA `bfd1709ca96a7919554e0254272feff8ba0b6c7f`; do not silently rewrite legacy fields.
2. `contracts/elx/v1/managed.proto.txt` is TARGET logical schema, **not runtime implementation**. Stage 2–7 must add actual authenticated, signed durable operations and Control consumer with matching hash.
3. `contracts/elx/v1/golden.json` captures unsigned exact bytes, SHA-256, semantics of existing signed evidence and proposed grant transcript; tests are not proofs that runtime enforces policies.
4. Stage 3 durable `savedPolicies.Version=1` migration MUST require authenticated Control reconcile, never grant admission from a restored snapshot. Stage 4 provisions grants and bindings without legacy JSON manual edits.
5. Stage 5 **must empirically settle** real VLESS REALITY Vision/XHTTP authenticated flow carrier; unsupported results are a block, not grounds to disable proof. Stage 6 only advertises flow-proof following real adversarial traffic tests.
6. Stage 7 owner fence must validate signed/durable Control-installed mapping locally prior to signed receipt. Core and Control release stay separately verified.
7. Current CI baseline: full tests and subscription regressions succeeded **in GitHub** on snapshot SHA, upstream-sync CI failed due to unset variable; not corrected in Stage 1.

## Operational barriers

- No AGENTS.md in recursive ElXray `main` tree at baseline; no open PRs or non-main branches observed. GitHub contents read-only to source, Stage 1 changes isolated on feature branch.
- Local full Go build NOT RUN here: available local `go1.23.2`, required `go1.27`, network-dependent module/toolchain fetch unavailable.
- Standalone tests passing does not assert managed `READY`. Physical VPN client guarantee and multi-host failure/freeze remain out of scope for Stage 1.
- Required release change: if any producer wire changes, update source fixtures + Control pinned consumer fixture in separate PR **before** enabling it.
