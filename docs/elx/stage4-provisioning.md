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
