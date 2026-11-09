# ADR-0001 — ElXray ↔ ElX-control: управляемый контракт v1

**Статус:** ACCEPTED FOR IMPLEMENTATION / not implemented. **Дата:** 2026-11-09. **Владелец core wire:** ElXray. **Владелец authority / journal / business identities:** ElX-control. **Stage:** 1/14.

**Base:** ElXray `8e4dbed76bef9755395945a4b7e2982d138ad62d`; Control `3e8891872f172eaeb92696c1527fd25ab158fa06`; UI `ee61adbc7b2c1dd544737321cf132f2a93f2c9a7`; Deploy `f753c9bed8df43196e7f50e4bb62c1c06c949d67`.
**Requirements:** `05_ELXRAY_updated_2026-11-09.md`, SHA-256 `7c3285909b4defaf3cd27726367beb82446721d9d253dd0e3fc7e62ac4c28cca`; `ElXray_Implementation_Roadmap_2026-11-09.md`.

## A. Подтверждённый CURRENT, не путать с TARGET

1. `app/policy/command/command.proto` == Control `internal/elxcontrol/corepolicy/wire/command.proto`, оба blob `bfd1709ca96a7919554e0254272feff8ba0b6c7f`; Go module у core — `github.com/xtls/xray-core` (go 1.27), у Control используется своя копия generated wire. Поля `uplink_bps/downlink_bps` — **байты/секунду**, несмотря на суффикс `bps`. Это legacy contract; не переименовывать/не менять существующие номера 1..6.
2. CURRENT gRPC `/xray.app.policy.command.SubscriptionService/{GetSubscription,SetSubscription}`; `/xray.app.policy.command.ControlLease/Renew`; `/xray.app.policy.command.ProfileFence/Drain`; `/xray.app.policy.command.RateBarrier/Prove`. Usage, pressure, accepted lease, policy proof передаются metadata на GetSubscription. Форматы зафиксированы в `contracts/elx/v1/golden.json`.
3. `checkLocalPeer` допускает TCP loopback и Unix socket **без удостоверения конкретного процесса**; signed Control lease проверяется в `RenewControlLease`, но не на каждом runtime increase. `savedPolicies.Version=1` сохраняет Base/Current/DeniedProfiles; это не durable grant/owner store. `elx-device-reserve-v1` в Control проверяет Ed25519 key, **но не доказывает, что client-supplied flow hash порождён реальным VPN handshаke**.
4. Действующий outage режим, при включённом `ELXRAY_REQUIRE_CONTROL_LEASE=1`, — краткосрочный **fail-closed**. `freeze` не реализован. Опубликованные ранее зелёные CI не удостоверяют managed device admission.
5. Программируемое ограничение местных процессов/managed transport, динамическое provisioning, защищённый device data-path proof, owner bind, child limits, полный readback — TARGET; в manifest их пока нельзя объявлять READY.

## B. Кто владеет состоянием и доверенными данными

| Тип | Canonical source / authority | ElXray |
|---|---|---|
| `accountId`,`entitlementId`,`deviceId`,`ownerId`,`operationId` | Control PostgreSQL | Только проверенная проекция, без прав на выдачу |
| `nodeId`,`executorId`,`authorityGeneration`, выданные allocations | Control и pinning node supervisor | Durable applied state; никогда сам не увеличивает права |
| `coreIncarnation`, local `storeId`, текущая active policy | ElXray + Deploy run identity | Подписанный readback; нельзя доверять node-supplied core key |
| `profileId` (VLESS UUID) | Control assigns; UI provisions technical config | Transport credential, не device identity и не proof |
| `installationId`,`displayName`,`manufacturer`,`model`,`platform` | Client reports; Control validates/stores | Display metadata НЕ используется для authorization |
| `keyFingerprint`,`keyGeneration`,`devicePublicKey` | Control enrollment | Validate only verified data-path proof (Stage 5–6) |
| Technical ports, REALITY, XHTTP, routing | UI desired config / Deploy | Core technical configuration, отдельно от signed grants |

Все UUID в протоколах канонические lower-case hyphenated RFC 9562 (wire: 16 октетов). Bytes: `uint64` объём, **B/s** для rates, 100 Mbit/s = 12_500_000 B/s. В JSON, доступном JS, `uint64/int64` — десятичная **строка**; не использовать IEEE-754 numbers для больших ревизий. Время UTC `RFC3339` для APIs, signed transcripts используют явно указанные integer Unix units. No implicit 0→unlimited. Parent disabled means DENY; child absent means INHERIT parent, child 0 is invalid unless distinct explicit DENY.

## C. TARGET v1 logical interface (Stage 2–7)

Source definition: `contracts/elx/v1/managed.proto.txt`. Это **schema/design snapshot**, не сгенерированный и не зарегистрированный runtime RPC. Namespace `elx.enforcement.v1`; consumer Control должен добавить отдельную versioned копию и explicit negotiation; старый `SubscriptionService` сохранится до миграции. Не пытаться маршрутизировать новые поля через старые uint64 RPC.

Required sequence:
1. Deploy boots **explicit managed instance** with node/executor ID, pinned Control public key, store and local authenticated agent channel. **Недостающий env-флаг, authority или store ⇒ NOT_READY/deny**, а не standalone fallback. Legacy standalone — только явно отдельная Xray конфигурация.
2. Node agent получает от Control durable signed grant для **точного nodeId+executorId+resourceId/entitlementId+authorityGeneration**, действующей expiry, cap up/down, generation/revision. Agent channels are authenticated locally (Stage 2: Unix socket filesystem ACL + peer credentials where supported; loopback не эквивалентен авторизации).
3. `ApplyManaged`: `header.contractVersion=1`, UUID `operationId`, SHA-256 `payloadHash` of canonical body, `expectedRevision` CAS, `newRevision>expectedRevision`, `coreIncarnation` и `authorityGeneration`. Same opId/same hash returns **persisted** result; same opId/different hash → `ALREADY_EXISTS`, no side effects. Lower epoch/old core/wrong executor → refusal. При неизвестном исходе после deadline → query ReadOperation; **не** предполагать rollback.
4. `InstallBinding`: подписанное разрешение Control связывает exact `profileId,entitlementId,deviceId,keyGeneration,ownerId,sessionGeneration,nodeId,executorId,coreIncarnation,authorityGeneration`. Core не принимает отдельный JSON «ownerId по словам клиента». State durable до admission. `Unbind` сначала durable deny/tombstone и quiesce.
5. `Admit`: authenticated VPN flow (не внешний API вызов), verified device key challenge + **transport-bound proof** (Stage 5 ADR), Control reservation (via trusted agent) и local installed owner generation должны относиться к одному flow. Пока нет доказанной привязки к channel/flow, **никакого payload**, включая first bytes. Копируемый UUID/VLESS URI сам по себе недостаточен.
6. `Fence`: durable tombstone generation перед закрытием активных и racing flows; ядро сверяет локальную установленную owner↔profile↔node↔core↔generation запись. Core signs only after drain; Control releases only with pinned core receipt and matching journal state. Unknown release держит owner занятым.
7. `ReduceRate`: live parent/child, atomic debit, quiet barrier/drain, distinct signed proof. Нельзя release allocation на receipt обычного SetSubscription.
8. `ReadStatus/Capabilities/ReadOperation/Usage`: distinguish submitted, persisted, applied, observed; explicitly advertise only experimentally proven capabilities. Missing reader ≠ success.

### Mutation and receipt states

`QUEUED` → `RUNNING` → `APPLIED` or `REJECTED`. `UNKNOWN` означает, что инициатор не знает итога, **не означает cancelled**. Cancel/timeout after durable intent может закончиться APPLIED. Each receipt binds `operationId,payloadHash,nodeId,executorId,authorityGeneration,newRevision,coreIncarnation,storeId,completedAt`. `ACCEPTED` от agent — не `APPLIED` от core. Receipt Ed25519 signature is over an explicit versioned binary transcript, verified using the **Control-pinned** core key; never use pubkey from receipt.

### gRPC error taxonomy (stable semantics)

| code | condition | safe Control action |
|---|---|---|
| `InvalidArgument` | malformed UUID/counter/oversize/non-canonical/bad semantic mode | permanent REJECTED |
| `Unauthenticated`, `PermissionDenied` | caller identity absent/foreign, grant signature wrong, over ceiling | deny and security signal; no apply |
| `FailedPrecondition` | wrong node/executor/incarnation/authority, stale grant, missing readiness, unknown owner mapping | reconcile; **never** admit |
| `Aborted` | expectedRevision CAS conflict | read actual revision, replan |
| `AlreadyExists` | reused operationId with different payloadHash | terminal conflict; no side effects |
| `ResourceExhausted` | slot, bound queue, state storage pressure | no admission; retry under policy |
| `Unavailable`, `DeadlineExceeded` | unknown transport/process/result | **UNKNOWN**, inspect operation/readback, retain commitments |
| `Internal`, `DataLoss` | durable store or invariant failure | degrade/deny; no success ACK |

Errors are **target mapping**, not a claim current legacy Commander already returns these codes.

## D. Canonical signed messages, versions and anti-replay

Preserve existing signed domains **unchanged**: `elx-control-lease-v2\n`, `elx-policy-v1\n`, `elx-session-fence-v2\x00`, `elx-rate-barrier-v1\n`, `elx-usage-v1\n`, `elx-pressure-v1\n`, `elx-lease-accept-v1\n`, `elx-device-reserve-v1\x00`. Exact bytes and hashes in `golden.json`; tests reconstruct from structured fields, check hash and alternate negative inputs. Existing sizes: fence 93 bytes unsigned, usage 48+64 signature, pressure 120+64, lease acceptance 88+64. `%x` over Go strings encodes **UTF-8 bytes of the string** (including ASCII hex challenge), not raw parsed challenge.

**NEW TARGET:** `elx-managed-grant-v1\x00` + 4 x UUID(16): `node,executor,resource,entitlement` + six unsigned 64-bit big-endian: `authorityGeneration,revision,notBeforeUnixSeconds,notAfterUnixSeconds,ceilingUpBytesPerSecond,ceilingDownBytesPerSecond` + one `disabled` byte (0/1). Sign exact bytes with Control Ed25519 key. `revision` and `authorityGeneration` must be >0; timestamps positive, notAfter>notBefore; ceiling>0 if enabled, finite; no unknown/extra fields in signed v1 struct. Golden test included. Separate signed operation receipt/owner binding formats must have distinct domain/version and deterministic wire fixture **before Stage 3/6 implementation**; no old domain repurposing. Changing existing signatures or protobuf field number requires a **new version and dual-read migration** (not silent edit).

**Anti-replay:** nonce unique to verifier+session, 16 bytes for existing read evidence, 32 bytes for Control device reservation; challenge expires and is single use under Control durable journal; seq/HWM per identity+core incarnation persisted; wrong node/owner/profile/key generation fails. No “HTTP challenge succeeded” ⇒ VPN-session-admitted shortcut. A copied `profileId` + clone without per-flow proof fails only in **TARGET** Stage 6, not in current code.

## E. Capability registry v1 — MUST be truthful

Registry identifiers frozen as naming **targets**:
`elx.managed.boot.v1`, `elx.agent.peer-auth.v1`, `elx.grants.signed-ceiling.v1`, `elx.state.durable-ops.v1`, `elx.profiles.dynamic.v1`, `elx.device.flow-proof.v1`, `elx.session.owner-fence.v1`, `elx.rate.child.v1`, `elx.rate.quiet-barrier.v1`, `elx.usage.period-hwm.v1`, `elx.outage.freeze.v1`, `elx.health.readback.v1`. Do **not** infer implementation from labels. Current `ProfileFence` alone is NOT `owner-fence`. Current Control `ReserveWithProof` alone is NOT `flow-proof`. Current lease-required mode is NOT `freeze`.

Manifest MUST include: `contractVersion,gitCommit,binaryDigest,coreIncarnation,storeId,nodeId,executorId,authorityGeneration,admissionMode,readiness,capabilities[]`; stable canonical IDs. Unknown capability is **unsupported**, never silently ignored. `managed.boot` only when actual guard passes. Readiness false on missing identity/store/key/proof/required transport. Health adapter may live in Control agent but MUST verify actual core PID/incarnation/readback, not self health.

## F. Migration map, stages 2–7

1. **Stage 2:** add managed boot guard and OS-auth agent channel; keep standalone explicit. Block legacy SetSubscription unmanaged mutation in managed; every rate increase requires current signed ceiling and authority+revision. No wire break until Control adapter mirrored.
2. **Stage 3:** migrate `savedPolicies.Version=1` to fail-closed versioned durable store with intent/operation dedup/HWM/signed leases. **Do not** auto-import old profiles as grant entitlements. Unknown/old snapshot ⇒ pending Control reconcile and deny. Unchanged current standalone config semantics.
3. **Stage 4:** install/update/retire technical profiles and grants with atomic binding; existing legacy JSON config is technical baseline only. Negative tests: no naked UUID activation; idempotent retry; rollback abort.
4. **Stage 5:** experiment and ratify **exact VPN channel-binding carrier** for Vision and XHTTP + Go protocol test client; Control's existing `ProofTranscript` input fields retained as interoperability basis, but `HandshakeHash/FlowBinding` must come from **core authenticated traffic**, not caller claim. This transport feasibility is deliberately **not asserted as resolved** by Stage 1; any different carrier gets `ADR-0002` and version bump before implementation. Fail-closed until proven.
5. **Stage 6:** implement verified wire proof and Control ReserveWithProof + local admission binding; only after real cloned-profile negative E2E allow `elx.device.flow-proof.v1`.
6. **Stage 7:** bind durable owner generation/fence to local installed authorization before signing, synchronize with Control ReleaseAfterFence; old signature `elx-session-fence-v2` may remain for compatibility if semantics are strengthened and no signed fields change. Upgrade version if signed fields change.
7. **Later stages:** rates, transports, usage, freeze, health, full acceptance, then upstream sync. Do not mark `freeze` ready based on lease loss.

**Cross-repo compatibility gate:** ElXray produces versioned proto/JSON, binary fixture, ADR, negative tests; Control adds identical consumer fixture & exact pin of compatible core SHA before new managed RPC used. UI & Deploy read version/status but **do not** write grants. Each repo has independent branch/PR when changes actually required; this ADR does not modify Control binaries.

## G. Mandatory adversarial vectors and what they prove

See `contracts/elx/v1/golden.json` and `scripts/check_elx_contracts.py`. Tests distinguish **byte contract invariants** (Stage 1) from future **runtime negative integration tests** (Stages 2–7). Required cases: foreign local process, missing managed env, increase above signed ceiling between renewals, stale epoch/boot/snapshot, duplicate opId different body, timeout with partially applied intent, wrong profile/owner/node/generation fence, cloned VLESS UUID with unbound channel proof, replay device nonce and wrong key generation, owner capacity concurrency, first-payload-before-authorization, no stale rate-barrier release. The negative list is **acceptance criteria**, not a claim current code enforces them.

## H. References and outstanding engineering gates

- Core source `app/policy/{runtime,lease,lease_acceptance,persistence,profile_fence,rate_barrier,pressure,usage}.go` and `app/policy/command/*.go`; `common/{subscriptionrate,sessionfence}`, `app/dispatcher/rate.go`.
- Control source `internal/elxcontrol/{corepolicy,session,policytransport,journal}`, `cmd/elx-control/agent.go`.
- Full physical channel-binding carrier **remains Stage 5 R&D**, not implicitly accepted. OS-specific process credentials and required service socket layout finalised in Stage 2 implementation; security requirement not negotiable. State migration requires explicit Control/Deploy implementation and rollback rules in Stage 3.
- CI on base SHA: subscription regression success `42381304934`, fence success `42381305145`, build success `42381304932`, upstream sync failed `42529336912`; upstream CI repair reserved for Stage 14.
