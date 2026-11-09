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
