# Stage 4: signed technical profile provisioning — WIP

Stage-4 branches are deliberately stacked on the **unmerged Stage-3** heads:
- ElXray stage-3 PR #21
- ElX-control stage-3 PR #22

## Completed in the first stage-4 implementation slice

- Defined the exact `elx-profile-grant-v1` Ed25519 transcript over action,
  operationId, nodeId, executorId, resourceId, profileId, subscriptionId,
  technical email and inboundTag, profileGeneration, authorityGeneration,
  policyRevision, and expiry.
- Added an ElXray model that **verifies the signature against the pinned Control
  public key and exact node/executor/resource**, rejects mutated grants,
  old generations, operationId collisions, expired grants, delimiter injection
  and reuse of a retired UUID.
- The model distinguishes `Pending`, `Installed` and `Retired`, and exposes
  no operation that grants VPN payload. An installed VLESS user is *not* an
  admitted device: stage 5/6 channel proof + Control owner reservation remain
  mandatory.
- Added both ElXray and Control golden fixtures. SHA-256 of canonical example
  transcript: `8282465f046f0dea2b02289253ab1e29cf053742a4fb2a7e4697d3187b4ef1cd`.
- Used existing upstream `HandlerService` and `proxy.UserManager` as the
  candidate technical user-management API instead of duplicating inbound
  listener configuration. **Do not call these old generic APIs from managed
  Control without an authenticated atomic provisioning adapter.**

## Not implemented yet — stage 4 is IN_PROGRESS

1. Reserve signed and budgeted technical profile issuance in PostgreSQL Control;
   durable intent plus idempotent operator-approved create/retire and generation HWM.
2. Journal `profileId → subscription/email/inboundTag/node/executor/resource/generation`
   in ElXray's on-disk store and restore **before managed listeners start**.
3. Add an OS-authenticated managed Unix RPC that durably commits the intended
   binding **before** `HandlerService/AlterInbound` adds the dynamic VLESS
   account, then verifies live user readback and signs the operation receipt.
4. For retiring a profile, deny new traffic and permanently tombstone the
   profile before removing it from every matching VLESS inbound. Drain/ACK
   must not release a Control owner until the proper stage-7 fence.
5. All existing generic `HandlerService/AddUser` and technical config reload
   paths must fail closed for unbound managed profiles; static standalone Xray
   operation must remain compatible.
6. Verify concurrency, two inbounds, repeat, partial commit, crash, disk full,
   fast restart, Control migration, signed ceiling and wrong executor through
   full Go 1.27/race/PostgreSQL tests. No stage-4 readiness advertised until then.

**Stage-4 status: IN_PROGRESS, NOT RELEASE READY.** Neither stage-4 PR may be
merged before paired stage-3 release gates pass.

## 2026-11-10 implementation checkpoint

Stage 3 has been merged into `main` in both repositories; these two Stage 4
draft PRs target `main` without creating more branches.

### Done in current Stage 4 branch (not yet accepted)

- Control PostgreSQL migration `023_technical_profiles.sql` adds permanent
  technical VLESS UUID reservation, immutable scoped operation IDs and
  `INTENT/APPLIED` storage. A row in `prepared` is *not* proof of a
  live VLESS user, device ownership or data-plane authorization.
- `journal.QueueTechnicalProfile` is a transactional, purchased-entitlement
  and Control-witness-checked enqueue: exact node/resource/executor, current
  authority epoch, currently committed core revision, subscription, and
  positive current rate grant must match. Collisions, stale epochs,
  unconfirmed rate mutations, foreign executor and reused UUID are rejected.
  Caller supplies canonical explicit short-lived start/end timestamps so
  retries with the same ID use the same exact digest.
- `cmd/elx-control enqueue-technical-profile` is a privileged operator-only
  interface; it gets node/executor/subscription/epoch exclusively from the
  protected current Control binding file. It does not enable traffic.
- Control `PolicyDelivery/TechnicalProfileNext` checks the currently
  authenticated node's mTLS identity and fresh protected Control bindings,
  reconstructs the original persisted exact-intent body, validates its
  SHA-256, and returns a short-lived Ed25519 signed `ProfileGrantIntent`.
  A missing/expired job is `NotFound`; there is no default trust of
  an agent-provided identity or public key.
- Xray `elxprovision.DecodeControlJob` parses the bounded JSON envelope
  strictly, disallows unknown/trailing fields and nested signatures,
  verifies the currently pinned Control signing key and exact
  node/executor/resource. No public subscription endpoint is involved.
- Generic `HandlerService/AlterInbound/AddUser` and the other six
  inbound/outbound mutations are now denied when running managed; standalone
  remains upstream-compatible. This prevents using old unauthenticated
  management calls as a substitute for the new signed provisioning flow.
- **Opt-in fail-closed enforcement:** setting
  `ELXRAY_TECHNICAL_PROVISIONING=1` requires managed mode and the existing
  durable `ELXRAY_OP_JOURNAL`. An authenticated VLESS request is refused
  before any payload dispatch while the user lacks Stage 6 device/owner
  authorization. In this stage no positive device authorization exists,
  therefore turning on the opt-in rejects *all* managed VLESS payload.
  **Never enable this opt-in on production nodes yet.** Default Stage 2/3
  behavior remains unchanged.
- Tests cover the exact Control/Xray signed grant transcript, malformed
  jobs, wrong executor, replay, expiry, concurrent alias/collision,
  durable DB `INTENT`, generic HandlerService bypass denial and
  lack of payload authority.

### Remaining P0 gates before Stage 4 DONE / main merge

1. Integrate the privileged node agent's technical-profile poll and its
   **OS-credential-authenticated** core prepare/install RPC. The signed
   preparation command must durably record its exact identity and hash
   *before* any `proxy.UserManager.AddUser`. The transport/flow and
   subscription-to-technical-email binding need to be explicitly covered
   by the signed payload; never guess Vision vs non-Vision flow.
2. Verify live VLESS readback and core incarnation before signing a
   dedicated `APPLIED` receipt. Control changes `INTENT` to `APPLIED`
   only after cryptographic verification, with no speculative resource or
   owner-slot release on unknown outcomes.
3. Implement safe update/retire, permanently tombstone old UUIDs and
   drain all related network flows. Config reload and direct static users
   must not bypass the managed profile binding.
4. Implement restart/replay of all committed technical mappings and prove
   safe recovery from power loss, disk-full, failed fsync and concurrent
   reconfiguration.
5. Run Go1.27 format/test/race/vet, real PostgreSQL node E2E,
   wrong-node/executor/signed-flow and no-payload-before-admission tests.
   Stage 3 deterministic WSL PASS cannot be substituted for Stage 4 E2E.

**Stage 4 remains IN_PROGRESS. Both PRs are DRAFT, not ready for merge.**
