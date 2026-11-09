# Stage 3 / Durable enforcement store — implementation checkpoint

**Status: IN_PROGRESS.** Base ElXray main `1c2f9d5a8fb3c74eebbb0914e48b933e5eb53424`, Control main `bde50292714124a16a76a3bf0f526bbf6465d110`. Stage 2 was merged on user instruction despite pending GitHub Actions; do not equate merge with passing production acceptance.

## First code slice

- `common/elxjournal/journal.go`: standalone crash-safe version-2 operation ledger. Caller-provided Control-verified operation identity includes `operationId`, `payloadSHA256`, `nodeId`, `executorId`, `resourceId`, `authorityGeneration`, `expectedRevision/newRevision` and kind.
- `Provision` explicitly creates new protected state **only when both state and anchor are absent**. `Open` refuses missing, corrupted or half-updated files, rather than creating an empty state after a crash.
- `Begin` persists an `INTENT` before a live change, checks resource revision and monotonic generation, denies a competing unresolved intent, returns exactly the prior receipt for an identical retry, and refuses reused IDs with altered signed-body identity.
- `MarkApplied` is only a library method; caller must perform authenticated live core readback first. It commits an `APPLIED` receipt and updates local revision/generation high-water marks. Unknown intent after restart is **not equivalent to cancelled or applied**.
- Each transition writes a 0600 temporary file, fsyncs, renames, fsyncs the containing directory, then writes and fsyncs a separately sealed anchor. Any mismatch on restart fails closed. The anchor's SHA-256 is an integrity check, **not** a signature or global anti-rollback proof.
- `journal_linux_test.go` fault-injects all six phases around both renames, replay, operation collision, stale generation, torn anchor, single-file rollback and missing state.
- Local test of the equivalent standalone Go standard-library prototype on Go 1.23.2: `GOPROXY=off go test -race -count=1 -v ./common/elxjournal` — PASS. This is NOT the complete Xray Go 1.27 CI result and the exact repository HEAD has not passed CI yet.

## Remaining Stage 3 P0 gates — not implemented

1. Wire the journal to **actual managed** `UpdateSubscription`, lease acceptance, rate reductions and core administrative service, rather than leaving it as a library. The current `SubscriptionService` proto has no `operationId` or `payloadHash`: a compatible new RPC/agent adapter (or trusted metadata with signed transcript) is required. Legacy SetSubscription cannot fabricate durable op receipts.
2. Recover persisted `leaseSeq`, `authorityGeneration`, store incarnation and denied profile generations across restart; currently `app/policy/manager.go` initializes lease maps empty. Stale signed lease delivery after reboot must not be accepted without a trusted Control reconcile. Changes to the current `savedPolicies.Version=1` need a versioned migration with no accidental privilege grant.
3. Couple journal intent, live limiter transition, policy JSON snapshot and signed readback. The current library cannot atomically commit two separate snapshot files plus a live operation. On a partial write, mark outcome UNKNOWN and deny all impacted traffic until Control verifies it. No acknowledgement from mere enqueue.
4. A coordinated rollback of image+anchor can pass local hash checks. To defeat it, Control must maintain a durable, independently monotonic revision/epoch/high-water witness and validate it before any recovered owner or grant is readmitted. No TPM/remote witness is implemented yet; never advertise durable anti-rollback as DONE.
5. Signed operation receipt transcript must pin `operationId,payloadHash,nodeId,executorId,authorityGeneration,newRevision,coreIncarnation,storeId`, with an explicit Control verifier and golden fixtures.
6. No extra managed rate token burst after restart, no stale closed owner resurrection, and error-injection at every intent/apply/receipt boundary. Cross-repo PostgreSQL and two-executor tests still required.
7. Run Go 1.27 formatting, `go test ./...`, race, vet, the complete ElX-control paired E2E and controlled restart tests when CI is available. Do not merge this draft until all required acceptance checks pass.

## Recovery decision table

| Durable observation | Meaning | Admission / allowed action |
|---|---|---|
| Matching image+anchor, `INTENT` | Mutation may or may not have reached core | UNKNOWN; deny affected resource pending authenticated Control reconciliation |
| Matching image+anchor, `APPLIED` | Journal transition completed | Still require current signed lease and core readback; no unilateral increase |
| Image/anchor mismatch | Mid-crash, tamper or rollback of one snapshot | NOT_READY; reject all mutating operations |
| Both files missing | Storage lost | NOT_READY, never recreate automatically |
| Same operationId, altered hash or identity | Replay/collision | Terminal conflict, no side effects |
| Lower revision or authority epoch | Old command | Reject, do not reset watermark |
| Both files restored together | Local check cannot detect rollback | Require independent Control high-water witness |

**Next action:** implement the managed mutation adapter and versioned policy migration, then prove exact caller/application semantics. This stage remains `IN_PROGRESS`; Stage 4 must not begin.

## Live implementation checkpoint: managed mutation adapter (same stage)

**New core code:** `app/policy/runtime.go` computes `ManagedUpdateHash` over the exact versioned `elx-managed-update-v1` transcript; `UpdateManagedSubscription` validates trusted Control node/executor/resource, generation, CAS and payload hash. For an explicitly opted-in journal (`ELXRAY_OP_JOURNAL`), anonymous legacy `UpdateSubscription` cannot mutate a managed paid policy. An accepted mutation persists `INTENT`, writes the policy snapshot, applies the live limiter and then persists `APPLIED`. The same operation is idempotent, a new payload with the same ID conflicts, and a crash between writes makes admission fail closed pending reconciliation.

**Local Commander wire:** legacy `SubscriptionService/SetSubscription` protobuf numbers remain unchanged. The authenticated Control agent now sends one each of `elx-op-id`, `elx-op-node`, `elx-op-resource`, `elx-op-executor`, `elx-op-generation` (uint64 decimal string) and `elx-op-hash` (lowercase SHA-256 hex). Core independently verifies the digest. These fields are authenticated by Linux Unix peer credentials and tied to the Control-signed v3 lease ceiling; user-supplied network metadata is not trusted.

**Signed receipt:** `GetSubscription` accepts `elx-op-readback-id` plus a canonical 32-byte hex `elx-op-readback-challenge`; only a durable `APPLIED` journal entry matching the CURRENT snapshot produces `elx-operation-receipt-bin`. This JSON envelope includes `version=1`, `operationId`, `payloadSha256`, `nodeId`, `executorId`, `resourceId`, `authorityGeneration`, `revision`, `coreIncarnation`, `storeId`, `completedUnixNanos`, and an Ed25519 `signature` (base64 in JSON). The exact signature transcript is:

```text
elx-applied-operation-v1
<hex of UTF-8 ASCII challenge>
<operationId>
<payloadSha256>
<nodeId>
<executorId>
<resourceId>
<authorityGeneration>
<revision>
<coreIncarnation>
<storeId>
<completedUnixNanos>
```

No trailing newline; all UUIDs canonical lowercase. Both repos pin the same golden SHA-256 `d354a37354ec0d68fa97f37352cb8cc456897832947772eee61d8ed81a47b8f7` and mutation-body hash `4255081ce063d5fc3a34d2099448e626e4202b80197d47d26b200ec2d19193bd`. Control's `policytransport.Confirm` now requires the original signed applied POLICY proof **and** this second pinned signed operation receipt before `journal.ConfirmApplied`, for every v3 executor-bound job. Policy readback alone no longer suffices in this path.

**Versioned policy snapshots:** when `ELXRAY_OP_JOURNAL` is active, core first opens a pre-provisioned journal with its paired `.anchor`, then requires `savedPolicies.Version=2` with the exact matching `StoreID`. A managed v1 snapshot, missing journal/anchor, different StoreID, stale baseline revision, stale authority or unresolved INTENT refuses to boot. Standalone and stage-2 transitional managed nodes without the new journal still use legacy v1. **The migration is not automatic**: provision/seed resource baselines only after independent Control approval. Never rewrite a live v1 state file by hand.

**Lease persistence:** an already verified v3 lease must durably advance resource-specific sequence, epoch and expiration HWM before admission; a storage error closes data-plane flows and fails the manager. On restart, the HWM rejects the previously accepted signed sequence. `common/subscriptionrate/limits.go` discards initial/dormant burst credit on managed boot and new lease admission, reducing double credit on restart.

### Remaining release-blocking work (Stage 3 not DONE)

1. Implement a **Control-authorized, audited offline v1 → v2 bootstrap/migration tool**. The current library primitives are not a migration procedure: operator-supplied baselines alone are not cryptographic proof of Control's latest epoch/revision.
2. Add a durable **remote Control witness** for `storeId`, monotonic operation HWM/revision and acknowledged core incarnation. Hash-linked image+anchor detects *single-file* rollback but **not simultaneous rollback of both files**. Compare witness before allowing a recovered grant/owner.
3. Handle unresolved INTENT after restart via explicit authenticated Control reconciliation rather than leaving the node indefinitely NOT_READY. No unilateral retry or automatic state reset is allowed.
4. Add full crash/partial-sync/disk-full and two-executor integration tests including real PostgreSQL and multi-process managed Unix peer credentials. Some target test suites still exercise legacy mode; do not promote them to Stage-3 acceptance.
5. Full Go 1.27 `gofumpt`, `go test ./...`, race, vet and cross-repo CI are **NOT RUN on the latest PR HEAD** because GitHub Actions is queued; local standard-library journal prototype tests do not replace these checks.
6. On-disk core operation receipt needs a separately pinned remote store incarnation for crash/rollback-proof handoffs. Stage 3 scope must not be confused with future Stage 4 dynamic provisioning and Stage 7 owner fences.

**Deployment:** These are *draft feature branches only*. Do not enable `ELXRAY_OP_JOURNAL` on production paid nodes until a verified migration has completed and both PRs pass their release gates. Stage 4 has not started.

## Checkpoint 2026-11-09: remote HWM, witness and offline migration

The paired Control PR #22 now adds checksummed `022_core_store_witness.sql`, transactional
`journal.ConfirmAppliedWithStoreWitness`, a protected `bootstrap-store-witness`
operator CLI and mTLS `PolicyDelivery/StoreWitness` RPC.

**PostgreSQL is authoritative**, not the node's JSON files. For each
`(nodeId,resourceId)` the independent row pins immutable `storeId`,
`executorId`, `authorityGeneration`, `coreRevision`, and the last
`(coreIncarnation,operationId)`. A new APPLIED receipt advances this HWM
**in the same PostgreSQL transaction** that marks its Control journal command
applied. A reused operation may be acknowledged idempotently but may not move
the witness backwards. A foreign store or older epoch is rejected.

**Freshness:** core generates a cryptographically random UUID on each boot.
The authenticated local agent obtains that nonce, asks Control to sign the
independent PostgreSQL witness bound to that exact nonce and a 15-second
window, and passes the signed witness alongside a v3 lease. With
`ELXRAY_OP_JOURNAL` configured, the core refuses a lease with no valid witness,
wrong `storeId`/resource/executor/generation, stale or foreign nonce,
mismatched core revision or missing locally APPLIED operation. It checks the
witness before installing a limiter deadline. Neither a self-signed node
assertion nor a prior-boot cached witness suffices.

**Paired environment settings (ONLY after approved migration):**
```text
ElXray:     ELXRAY_MODE=managed
ElXray:     ELXRAY_OP_JOURNAL=/var/lib/elxray/operations.json
ElX-control ELX_AGENT_MANAGED=1
ElX-control ELX_AGENT_STORE_WITNESS_REQUIRED=1
```
All other stage-2 signed lease, node key, trusted bindings and Unix agent
identity settings remain mandatory. The stage-3 option is **not production
ready without passing complete Go/PostgreSQL/rollback and two-executor tests**.

**Operator-only v1→v2 migration, never on a live core:**
1. Record a verified SHA-256 of the original **nonempty** v1 snapshot,
   review the exact Control mapping, snapshot revision, grant epoch and
   denied profiles. Stop the core and retain an independently stored backup.
2. Choose a unique immutable `storeId` and have an operator with DB
   credentials run `elx-control bootstrap-store-witness` with exact
   node/resource/executor, Control epoch and core revision; the action
   requires the literal `ACK_OFFLINE_CORE_BASELINE` and validates the
   active Control binding, durable DB revision and epoch. This is privileged
   administrative approval, **not an automatic core attestation**.
3. Run `go run ./cmd/elx-stage3-migrate -state /ABS/policy.json
   -journal /ABS/operations.json -bindings /ABS/bindings.json
   -denied-generations /ABS/control-confirmed-denial-generations.json
   -store STORE_UUID -expected-sha256 EXPECTED_OLD_SNAPSHOT_SHA256
   -approve OFFLINE_CONTROL_APPROVED` only while the Linux policy
   state lock is held exclusively by the offline migration process. It
   creates a write-once v1 backup, explicitly provisions the journal,
   seeds per-resource revision/epoch, preserves all VLESS-denial tombstones,
   then atomically replaces the snapshot with version 2 and the same storeId.
   A half-migration aborts startup; **do not blindly retry or delete files**.
4. Before enabling managed service, verify witness/manifest matches in
   Control and that the core will reject v1/wrong-store/replayed leases.
   Recovery from an ambiguous migration requires explicit operator audit.

**Profile tombstones:** every managed signed VLESS drain records a durable
generation-indexed profile-denial tombstone in the journal before signing
the active drain. The v2 snapshot denial set and journal tombstones must
match exactly at boot. Replacing both local files with an older snapshot
still requires a fresh remote PostgreSQL witness to renew the lease.
The stronger owner→profile→node generation authorization remains Stage 7.

**Locally reproducible offline test runner:** `ELX_CONTROL_DIR=/path/to/ElX-control
bash scripts/check-stage3-local.sh`. It checks Go version against
`go.mod`, formats, focused race tests, `go test ./...` and `go vet ./...`
for BOTH repositories. `ELX_TEST_POSTGRES_DSN` is mandatory for real
PostgreSQL tests; without it they are reported **NOT RUN**, never PASS.
Do not point this DSN at a real paid/production database.

### Still NOT DONE
- Signed initial/offline core baseline proof and operator-approved migration
  E2E with a real PostgreSQL instance and protected systemd identities.
- Automatic authenticated reconciliation of INTENT with unknown outcome
  after crash or split-brain; currently this safely blocks admission.
- Full Go 1.27 CI/race/static/transport matrix at the actual PR commits;
  GitHub checks queued, and this container only has Go 1.23.2 plus no
  local PostgreSQL. Isolated journal/witness tests alone are insufficient.
- Long-running journal compaction/tombstone retention without ID replay,
  disk-full fault injection against real Xray process, and multi-executor
  partition/restart tests.

**Current status: IN_PROGRESS. Do not merge PR #21 and Control PR #22 yet.**


## 2026-11-10 checkpoint: profile rollback and CI recovery

**Witness protocol upgraded to v2 (v1 MUST NOT be accepted when the journal is active).** Control derives a cryptographic SHA-256 of the sorted UUID/generation pairs from its authoritative PostgreSQL `elx_session_owners` in `draining` or `released` state. Each short-lived Control-signed store witness now carries `TombstonesSHA256` alongside immutable storeId, executor, epoch, core revision, core incarnation/last operation, fresh boot nonce and validity window. ElXray computes the exact same digest from local durable VLESS profile tombstones. A mismatch refuses a managed lease: restoring **both** older local files cannot silently roll back a Control-approved revocation. The signed transcript prefix changed to `elx-control-store-witness-v2`; Control and core test the shared golden digest `0a4db3a3f4127c05fce5a9db65ece76326fafadc9025f3f5b3167c74609258db`.

When migrating a v1 snapshot that contains denied VLESS profiles, the old file lacks each profile's original generation. The offline migrator now requires an additional private JSON map of `{<canonical-profile-uuid>: <Control-confirmed-positive-generation>}`, given using `-denied-generations`. This map MUST equal exactly the v1 denied profile set. Missing, extra, duplicated or zero-generation values block migration before any new files are provisioned. Importing fabricated generation 1 is unsafe. Empty v1 denial sets can omit this argument.

**CI fact, not assumed success:** GitHub Actions revived. On the earlier heads it exposed a Control compile error (`policytransport/service.go` shared `err`), an explicit standalone-mode regression in the legacy two-node smoke test, and Xray `gofumpt`/profile-fence formatting failures. The former two were corrected in Control PR #22, and the exact Go 1.27 formatter diff for 17 files was applied in ElXray PR #21. Because subsequent commits change both heads again, neither an old successful build nor a queued check is evidence of current-head PASS.

**Local verification on this assistant host (not full repository):** Go 1.23.2 standard-library golden-contract mirror: `go test -race -count=1 -v ./...` and `go vet ./...` PASS for signed receipt, mutation hash, signed store witness v2, and profile-denial HWM parity. Go 1.27, complete Xray+Control source clones, PostgreSQL and Docker are unavailable locally; network/DNS cannot clone GitHub. This mirror is not the production pair, and must not be used alone to declare stage 3 DONE.

**Release gates remain open:** run `scripts/check-stage3-local.sh` from actual adjacent branch checkouts with Go >= 1.27 and `ELX_TEST_POSTGRES_DSN` for isolated PostgreSQL; investigate any failures. For unknown outcomes, the current safe behavior deliberately refuses boot on unresolved INTENT until an operator reconciles with the authoritative Control state, not automatic abandon or replay. The current permanent stop at 16 MiB journal size is also safe but needs a bounded archival/compaction operating procedure. No stage-4 coding or production deployment until these release conditions are met.
