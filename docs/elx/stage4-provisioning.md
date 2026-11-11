# Stage 4 — dynamic technical VLESS provisioning (IN_PROGRESS)

Paired pull requests:
- ElXray: https://github.com/ElXnet/ElXray/pull/22
- ElX-control: https://github.com/ElXnet/ElX-control/pull/23

Stage 3 has already been merged to both repositories' `main`.
These Stage 4 PRs target `main` and are deliberately kept DRAFT until
the signed installation/retirement, crash recovery and E2E gates pass.

## Security boundary

A **technical VLESS profile** is a preallocated account UUID, not a
verified physical device, session-owner, concurrent slot or right to
send VPN payload. A Control-signed `prepare` intent cannot admit traffic.
Device/channel proof and Control owner admission belong to later stages.
Never claim physical device identity from a UUID.

Default Stage 2/3 operation is preserved. Opt-in
`ELXRAY_TECHNICAL_PROVISIONING=1` requires `ELXRAY_MODE=managed`, a
provisioned durable `ELXRAY_OP_JOURNAL`, signed leases, a protected local
Unix Commander, a dedicated non-root agent and pinned Control keys.
The opt-in currently denies **all** managed VLESS payload because the
later owner/device-proof mechanism has not been implemented.
**Do not activate the opt-in on production VPN nodes yet.**

## Implemented (still under test)

1. Control `internal/elxcontrol/corepolicy/profile_grant.go` and Xray
   `common/elxprovision/grant.go` share the byte-exact Ed25519
   `elx-profile-grant-v1` transcript, including operation, target,
   executor, resource, subscription, inbound/email, profile UUID,
   generation, authority and revision, plus validity timestamps.
   The canonical fixture SHA-256 is
   `8282465f046f0dea2b02289253ab1e29cf053742a4fb2a7e4697d3187b4ef1cd`.
2. Control PostgreSQL migration `023_technical_profiles.sql` creates
   immutable technical UUID reservation and INTENT/APPLIED ledgers.
   `journal.QueueTechnicalProfile` pins paid entitlement, current
   rate grant, core store witness, executor, revision and epoch.
   Idempotent exact retries are allowed; changed op IDs/UUID aliases,
   expired grants, revoked subscriptions and uncommitted mutations are
   rejected. It creates no live user.
3. The privileged Control `enqueue-technical-profile` command sources
   node/resource/executor/subscription/epoch from protected bindings.
   PolicyDelivery `TechnicalProfileNext` rechecks the same current
   binding and paid DB grant and signs a short-lived profile job only
   after a matching durable INTENT exists. Node identity comes from mTLS.
4. `common/elxprovision.DecodeControlJob` performs strict bounded JSON
   and pinned-key signature verification, rejecting unknown/trailing
   fields, nested signatures, wrong node/executor/resource, replay,
   stale generation and changed payload.
5. ElXray's `common/elxjournal` v2 durable snapshot now supports an
   **optional**, backwards-compatible `technicalProfiles` map.
   `RecordTechnicalPrepared` persists an exact PREPARED identity
   before any later user mutation, rejects collisions and old denied
   UUIDs, and survives safe restart without silently granting payload.
   The existing Stage 3 journal cannot be reconstructed after loss.
6. ElXray `app/policy/technical_preparation.go` checks the exact
   Control-signed payload against the currently pinned lease,
   subscription, executor, resource, authority and core policy revision.
   The separate `/elx.core.v1.TechnicalProfile/{Prepare,Readback}`
   gRPC service in `app/policy/command` requires the already enforced
   Unix SO_PEERCRED local agent. The readback reports PREPARED, **never
   installed/applied or device admitted**.
7. Control's `corepolicy.Client` sends the exact signed job to that
   local RPC. `policytransport.ApplyTechnicalPreparation` verifies
   the trusted Control public key and exact local assignment, checks
   core PREPARED readback plus local persisted readback, and **does not**
   ACK APPLIED or release any slot. Opt-in
   `ELX_AGENT_TECHNICAL_PREPARE=1` integrates this poll into the
   existing node agent, requiring managed signed-lease mode.
8. Generic upstream HandlerService inbound/outbound mutation methods
   (including AddUser) are refused in managed mode, preventing an
   unsigned bypass of the new dedicated path; standalone behavior
   remains upstream compatible.
9. Added negative/race-friendly unit tests for exact transcript,
   bad signatures/foreign executor, persistence and restart,
   denied UUID/collision, RPC peer auth, bounded transport and
   non-admitting readback. Also corrected a Windows MASQUE test to
   check a shared port is available for both TCP and UDP before launch.

## 2026-11-10 continuation: signed job JSON ambiguity

Both Stage-4 branches now reject duplicate JSON object keys (including
case-folded aliases matched by Go's `encoding/json` struct decoder) before
accepting a signed technical preparation envelope. The check is recursive,
including nested `Grant` fields, and rejects concatenated documents.

- Core: `common/elxprovision/json_keys.go` is invoked by
  `DecodeControlJob`; `wire_test.go` has negative cases.
- Control agent: `policytransport/profile_job_json.go` is invoked before
  unmarshalling `TechnicalProfileJob`; `profile_job_json_test.go` covers
  exact duplicates, case aliases and trailing documents.
- Core PR #22 head at this change: `56d0539a8e5be69cfa93a21c24585e1d1c6e7354`
  (additional documentation commit follows).
- Control PR #23 head: `ae15c07a69c97fc9aa2de3978f588eb2abc83337`.
- CI for these heads was **QUEUED** when checked. No Go unit/race/vet
  results for these exact heads are claimed as passing. Core local
  full-repository testing was not possible in this execution environment.

This is a narrow security hardening, **not** completion of dynamic VLESS
installation, signed INSTALLED proof, retirement, durable reconciliation or
cross-repository E2E. Stage 4 stays IN_PROGRESS, both PRs stay draft.

## 2026-11-10 continuation: effective VLESS identity and signed INSTALL

This section supersedes the previous "PREPARED only" description for the
**draft branch**, without claiming production readiness.

**Added / awaiting exact-head CI validation:**

- VLESS `MemoryValidator.Add` now serializes user/email insertion and refuses
  existing **normalized lookup UUIDs**. VLESS's `ProcessUUID` zeroes bytes
  6 and 7; two distinct printed UUIDs may therefore authenticate as the same
  VLESS user. Negative sequential and racing tests were added.
- Journal rejects prepared UUIDs aliased to an existing profile or permanent
  denial, and detects equivalent duplicates during durable restore.
  Control's PostgreSQL reservation checks the same effective key, with a
  unique expression index in draft migration `023_technical_profiles.sql`.
  Before using this migration on a database where 023 was already applied,
  a separate forward migration and a review of existing identities is needed.
- A new **`elx-profile-grant-v2`** Ed25519 transcript binds the exact
  `Flow` value (`xtls-rprx-vision` or empty) for technical `INSTALL`.
  Version-1 PREPARE golden vectors are unchanged. The v2 cross-repository
  SHA-256 vector is
  `0584a0a5bab7efee61d1c244cf0ec45deea7730f0dbe562c15c564273f3d033a`.
- The core exposes authenticated Unix Commander `TechnicalProfile/Install`
  on the Stage-4 opt-in. It requires a separately signed v2 INSTALL
  referring to the matching durable PREPARED record, a fresh live lease,
  exact node/resource/executor, existing VLESS inbound and paid policy.
- The journal saves `INSTALLING` **before** changing the live VLESS user.
  A crash in this state prevents managed startup until reconciliation.
  `INSTALLED` is saved only after the live VLESS user is read back and
  matches UUID/email/flow. Local readback also rechecks live registration.
  No payload admission is granted by either state.
- A corresponding Control corepolicy client adapter can call the protected
  INSTALL RPC; this alone cannot issue a job or record a Control APPLIED ACK.
  Journal, signature, peer-auth, alias and replay regressions were expanded.

**Still P0 / no rollout:**

1. Control must **durably queue, sign, deliver and reconcile** INSTALL
   independently of the PREPARE grant. The existing Control agent currently
   polls PREPARE only; a client adapter is not a job issuer.
2. Implement core-signed `INSTALLED` evidence bound to core incarnation,
   operation, store and live user; verify it in Control before moving
   INTENT to APPLIED. A local unsigned readback is insufficient.
3. Reconcile interrupted `INSTALLING` operations and rehydrate INSTALLED
   profiles after reboot (or explicitly quarantine/reprovision), with exact
   trust and attestation checks. Current boot **fails closed** on uncertain
   install and does not silently admit payload from stored INSTALLED.
4. Implement signed retire/update and permanent drain across inbounds,
   plus rollback/reload/restart and concurrent duplicate tests.
5. Complete the exact paired-head CI, PostgreSQL two-node E2E, fsync/power
   loss tests, Linux protected socket tests, and externally unavailable
   tests as NOT RUN. Earlier Windows journal test failed because Windows
   rejects Unix-style directory fsync; tests now skip only that unsupported
   managed durability environment, rather than weaken production fsync.

**Security:** Do not enable `ELXRAY_TECHNICAL_PROVISIONING=1` on production.
The opt-in continues to reject all managed VLESS payload until later
device-proof/owner admission is implemented. Draft PRs stay unmerged.

## 2026-11-10 update: signed core proof and Control INSTALL queue

The paired draft branches now contain a more complete **non-admitting**
technical INSTALL pipeline, pending CI and two-node integration validation:

1. Control migration `024_vless_effective_uuid.sql` enforces normalized VLESS
   UUID uniqueness without rewriting already-checksummed migration 023.
   Migration `025_install_intents.sql` adds durable version-2 INSTALL intents
   and signed flow. `QueueTechnicalInstall` reserves only an existing
   prepared profile with current paid authority; `NextTechnicalInstall`
   projects an exact, non-expired pending operation for the assigned
   node/resource/executor.
2. The Control server publishes `TechnicalInstallNext` over authenticated
   mTLS, independently signs the v2 INSTALL, and the opt-in node agent
   (`ELX_AGENT_TECHNICAL_INSTALL=1`) calls the protected local ElXray
   `TechnicalProfile/Install` over Unix SO_PEERCRED. Enabling the agent
   also requires `ELX_AGENT_TECHNICAL_PREPARE=1` and the already-pinned
   Control lease key.
3. The core journal records `INSTALLING` before AddUser and persists
   `INSTALLED` after actual readback. Another protected local RPC
   `TechnicalProfile/InstalledProof` signs a domain-separated
   `elx-vless-installed-proof-v1` receipt with the core's own key, binding
   install transcript, profile, operation, node/resource/executor,
   authority generation, policy revision, durable store ID and core boot.
4. Control accepts `TechnicalInstallConfirm` only from an authorized mTLS
   node and checks the exact installed receipt against **independently
   pinned** PostgreSQL `elx_core_identities` and
   `elx_core_store_witnesses`. Only after verifying the Ed25519 signature,
   immutable pending digest and expected store/boot does the same DB
   transaction mark the technical operation `APPLIED` and profile
   `installed`. This does not create a device/owner slot or permit payload.
5. Paired tests cover v2 transcript goldens, replay, forged receipts,
   different store/boot, alias UUIDs and durable INSTALL intents; the
   PostgreSQL fixture now tests an atomic authentic receipt and idempotent
   confirmation.

A separate signed-usage scheduler E2E was failing because the fixture ran
the `usage0/usage1` reporter processes as root despite a managed Unix
Commander bound to the unprivileged `nobody` agent UID. The test fixture now
demotes *both* node agent and signed-usage reporter before accessing the
protected socket, instead of weakening SO_PEERCRED. Exact-head CI acceptance
for this correction remains unconfirmed.

### 2026-11-10 continuation: bounded signed RETIRE and scheduler CI

Stage 4 now includes a distinct Control-authoritative v2 `RETIRE` reservation,
mTLS delivery, protected core `Retire` and `RetiredProof` methods, and Control
verification against its independently pinned core key/store/boot before the
transactional technical-profile `retired`/operation `APPLIED` transition.
The core writes `RETIRING` and a permanent effective-UUID tombstone in one
durable journal snapshot **before** attempting live VLESS removal. It also
denies the profile in its runtime session fence and waits for tracked flows
to close. Unknown outcomes retain the tombstone and fail closed. A retired
email may be reused only by a new profile with a *different* effective VLESS
UUID; the retired ID or its alias is never resurrected. No owner slot,
bandwidth allocation or paid subscription entitlement is freed by RETIRE.

Control's two-node signed-demand scheduler E2E has progressed past its former
`usage0/usage1` Unix peer-credential mismatch: both signed core pressure
samples are now accepted. A new failure then exposed that the agent tried a
reserved speed **increase** against an older signed lease ceiling. The Control
lease issuer now derives the ceiling from the maximum of the committed rate
and an existing durable, not-finalized `elx_rate_moves` reservation. The
agent only retries the *same* managed operation after obtaining a new
Control-signed lease; invalid signature/identity paths remain denied. New
end-to-end CI for this fix is still queued, not a confirmed PASS.

These changes are on Draft branches and have NOT completed paired-head CI.
Review these limitations before promotion:

- Core restart after `INSTALLING` / `RETIRING` remains quarantined, not
  silently reconciled. Recovery must establish the actual live VLESS state
  and obtain Control-approved rebind/rebuild evidence before release
- Signed 60-second operation expiry and lost Control ACK need a safe read-only
  recovery protocol to reconcile installed/retired outcomes without replaying
  stale mutations
- All-inbound effective-UUID alias draining and no-bypass reload require a
  complete cross-inbound test on real VLESS before declaring coverage
- A complete PostgreSQL-backed two-core PREPARE/INSTALL/RETIRE/confirm/deny
  E2E on mutually pinned exact heads has not passed yet
- Retire and install Go formatting, static, race, and platform CI are pending

The workflow in `docs/elx/stage-workflow.md` now formally separates
`IN_PROGRESS`, `TESTING` and `DONE`. The Stage-4 status is still
`IN_PROGRESS` while these P0 functional/proof gaps remain.

### 2026-11-11: read-only lost-ACK recovery (Draft)

A live core may finish an independently signed, durably journaled v2
`INSTALL` or `RETIRE` while the Control confirmation is lost. After the
short-lived original signed job has expired it must **never be replayed as a
fresh mutation**. This branch now provides:

- Core `RecoverInstalledProof(profileID/operationID)` and
  `RecoverRetiredProof(profileID/operationID)` over the original authenticated
  local Unix RPC, requiring the **exact** immutable journal terminal state,
  the originally recorded transcript digest and current live VLESS
  presence/absence. The core signs a new receipt using the protected core
  private key and new/known boot identity, **without a new AddUser/RemoveUser**.
- Control's mTLS-scoped, bounded `TechnicalRecoveryNext` returns at most
  eight old `INTENT` install/retire operations. The agent validates node,
  executor, resource, generation and independently pinned core public key.
  It relays only a valid signed receipt to the existing PostgreSQL
  `TechnicalInstallConfirm` / `TechnicalRetireConfirm` transaction, which
  independently reconstructs the original Control transcript and checks
  pinned store/boot/identity.
- Failure or no proof leaves the central operation in `INTENT`, preserving
  purchased capacity and denying any implied owner/device admission.
  Uncertain `INSTALLING` or `RETIRING` is NEVER auto-promoted; an operator
  must reconcile it with independent evidence. This read-only path is
  disabled unless `ELX_AGENT_TECHNICAL_RECOVERY=1` is explicitly set in
  managed agent mode.

**Status:** code and negative tests submitted; exact-head PostgreSQL,
two-core end-to-end recovery (expired job, lost Control ACK, restart and
foreign signed proof), race and static checks are still **NOT RUN/PENDING**
at this new SHA. This feature is NOT production-authorized and Stage 4
remains `IN_PROGRESS`.

The attested scheduler E2E exposed an additional race when a recent
signed lease's independent store HWM became stale during a reserved rate
reduction. The managed agent now quarantines *only* that exact proof-refresh
denial as a pending retry, never grants rates or confirms an operation
without core-signed APPLIED. Verify continued progress under a two-node
real-core scheduler test before moving this item to `TESTING`.

### Remaining release-blocking gates

- CI on the paired latest heads, including gofumpt, go vet, full Go/race tests,
  Linux/Windows/macOS where applicable, PostgreSQL/real core protected-socket
  two-node E2E and signed technical install/confirmation traffic denial
- Durable reconcile of crashed `INSTALLING`, lost proof/ambiguous COMMIT,
  and safe installed-user rehydration or quarantine after restart
- Independently signed RETIRE/update, all-inbound lookup/flow drain and
  permanent tombstones under untrusted stale Config/Control
- Anti-bypass verification for static JSON, hot reload, rollback, duplicated
  Control writers and hardware failures
- Only after those gates pass: mark PRs ready and evaluate merge/deployment

**DO NOT MERGE OR DEPLOY.** Stage 4 is still `IN_PROGRESS`;
`ELXRAY_TECHNICAL_PROVISIONING=1` must not be enabled on production nodes.
The Stage-4 technical user **never** authorizes VPN payload without later
device proof and owner assignment.


## 2026-11-11 final implementation batch (PENDING paired CI)

The core preflights normalized authentication UUID collisions across every
currently registered VLESS inbound, before INSTALLING. It rechecks all
inbounds after AddUser and refuses core-signed recovery proofs when a shadow
alias exists. A failed post-install scan quarantines INSTALLING; it never
pretends success. A RETIRE only signs absence after the effective UUID is
absent globally, and the permanent tombstone remains durable.

A read-only offline `cmd/elx-technical-inspect` validates the fsynced
journal/anchor, original operation, independently pinned Control StoreID and
an exclusive stopped-core policy lock. An `INSTALLING`/`RETIRING` state is
operator isolation, not a successful repair. See
`docs/elx/stage4-operator-recovery.md`. Independently signed offline
operator-authorized quarantine/abort closure of the Control INTENT remains
P0; do not merge or deploy before that protocol is designed and proven.


## 2026-11-11: managed VLESS inbound bootstrap UUID fence (pending CI)

The core now validates every statically configured VLESS user at inbound
construction against the *whole* durable technical profile ledger
(PREPARED, INSTALLED, RETIRED) and the permanent denied-profile tombstones.
Matching effective VLESS UUIDs—including normalization aliases in another
inbound—fail the core/inbound bootstrap **before listeners start**. This
prevents a static configuration rollback or new inbound construction from
silently shadowing an existing Control-issued technical identity.
The guard does not change non-opted-in / standalone behavior and never
grants a technical UUID owner/device admission. Installed/retired live
readback now acquires the subscription mutation lock and verifies the
complete VLESS inbound scope rather than only the target inbound.

Large decommission/rebootstrap behavior remains a cross-service architectural
requirement; see [stage4-architecture-handoff.md](stage4-architecture-handoff.md).
Do not promote this note or Stage 4 to DONE before exact-head CI and all
remaining release gates pass.

## 2026-11-12: hot reload / inbound publication serialization (Draft)

ElXray now revalidates the candidate handler's actual VLESS validator users
while holding the SAME `subscriptionMu` used by signed
PREPARE/INSTALL/RETIRE. The mutex remains held through the inbound-manager
registration and listener start; the lock order is always
`subscriptionMu → inbound.Manager.access`. This prevents constructing an
inbound before Control's UUID reservation and publishing it afterwards.

Only an exact journal-INSTALLED identity on its bound inbound tag, with the
matching original UUID, email, and flow, can be rehydrated. A PREPARED UUID,
RETIRED tombstone, normalized UUID alias, wrong tag or a non-VLESS replacement
must fail closed. Removal of a tag still containing a PREPARED or INSTALLED
Control-owned profile is rejected. Standalone/non-opted-in handler lifecycle
preserves upstream behavior. A failed handler Start is removed from the
manager rather than leaving a discoverable partial hot-reload.

Tests cover serialized commits, concurrent stale reload, missing/rebound
INSTALLED identity, standalone compatibility, and failed listener startup.
These changes are deliberately core-only and DO NOT create device admission
or a new ElX-control endpoint. They require exact-head CI and a dedicated
live hot-reload race E2E before Stage 4 is DONE.
