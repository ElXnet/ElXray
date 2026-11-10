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

## P0 work still required before DONE

1. Add *durably verified dynamic* VLESS `AddUser` through the dedicated
   managed path, including signed flow configuration (Vision vs empty),
   exact authorized inbound, readback and safe crash interruption.
   `PREPARED` must never be mistaken for `INSTALLED`.
2. Implement signed, independently core-attested `INSTALLED` receipt.
   Control may advance its `INTENT` to `APPLIED` only after checking
   exact operation/UUID, verified core incarnation, journal HWM and
   live registered user. Lost ACK and uncertain outcomes stay pending.
3. Implement safe profile update/retire, permanent tombstone and drain
   across all matching inbounds/active flows, without unverified
   release of owner or bandwidth.
4. Protect managed restart and config reload from static JSON bypass,
   restore installed mappings and verify crash/disk-full/fsync/replay.
5. Pass CI gofumpt, Go tests, critical race/vet, PostgreSQL-backed
   Control/core two-node E2E, wrong-node/executor and payload-denial
   tests on the **paired Stage 4 heads**. Unsupported network tests
   and external acceptance must remain explicitly NOT RUN when skipped.

**Not merged.** Until all P0 gates are passed, Stage 4 remains
`IN_PROGRESS` and production rollout is blocked.
