# ElX Stage 4 — architecture handoff and repository ownership

**Status:** ARCHITECTURE REVIEW REQUIRED for cross-service additions.
**Owner of this implementation chat:** ElXray core.
**Related Draft PRs:** [ElXray #22](https://github.com/ElXnet/ElXray/pull/22)
and [ElX-control #23](https://github.com/ElXnet/ElX-control/pull/23).

This note supports the architectural conversation
**«Разработка VPN клиента (арх)»**. It does not silently modify the
existing four authoritative specification files, and is not a signed-off
rewrite of their content. The available archived context gives their
ownership boundaries but does not include their entire ZIP payload.
Review against the four complete v2.0 specifications before acceptance.

## Scope decision

| Repository | Owns | Does NOT own |
| --- | --- | --- |
| `ElXray` | VLESS identity validation, authenticated traffic path, enforcement of signed policy and session limits, per-flow lifetime and disconnect, durable local journal and fail-closed restart, signed factual core receipts | Payment, tariffs, entitlement or owner-slot allocation, database leadership, operator approval |
| `ElX-control` | Central entitlement/slot authority, per-node bandwidth allocations, FUP, persisted operation intents, authentication of control actors and nodes, independent store/boot witnesses, distributed policy confirmation | Modifying the VLESS runtime directly, trusting unsigned agent readback as proof, arbitrary local journal repair |
| `ElX-ui` | Explicit operator workflows, identity-scoped approvals, device/lease/incident status and audit visibility | Authorizing an inbound user independently of Control |
| `ElX-deploy` | Node lifecycle, isolated rollouts, health, durable deployment artifacts, backup, recovery, master failover and external fencing | Silently resetting journal/Control generations to unblock a service |

Small compatibility and contract fixes can be committed directly to the
corresponding repository with an integration test. A new service, state
machine, cross-repository operation or change to payment/HA authority
must be specified here and in the canonical v2.0 architecture before
implementation.

## Current ElXray Stage-4 responsibilities

1. Validate globally equivalent VLESS UUIDs, not just printed UUIDs or
   identical user emails. The VLESS authentication lookup normalizes
   some UUID bytes; an alias must not bypass another inbound's identity.
2. Reject a static JSON user that collides with a durable technical
   PREPARED, INSTALLED or RETIRED identity, or a retained denial tombstone.
   This must execute before inbound listeners start and on every inbound
   construction/reload. Do not fall back from managed mode to standalone.
3. Use an immutable signed PREPARE → INSTALL → RETIRE operation sequence.
   The node must record INSTALLING/RETIRING durably before live mutation,
   quarantine unknown outcomes and never claim a successful operation on
   the basis of a local unsigned snapshot.
4. On RETIRE, permanently deny the original effective UUID, stop and
   wait for established flows, verify absence across all VLESS inbounds,
   then sign factual proof; no automatic paid slot release.
5. A technical VLESS UUID is NOT a device identity or owner admission.
   Stage 4 must remain non-admitting until the separately specified
   device/owner proof protocol is implemented.

## Cross-service change request: safe decommission and rebootstrap

**Status: UNDESIGNED / NOT APPROVED for implementation in Control or Deploy.**

The existing Control Draft PR already contains an administrative
`quarantine-technical-node` proposal and migration 027. That work was
started ahead of full architecture review. It must remain **Draft** and
requires explicit reconciliation with this specification before merge.
In particular, an operator claiming external fencing is not equivalent
to cryptographic evidence that a remote VPS has stopped.

The architecture should define one explicit, audited, monotonic
`quarantine → externally fenced → decommissioned → new node provisioned`
workflow (names provisional). It must include:

- **Independent authority and approvals:** operator permissions, approval
  scopes, audit log, idempotency, two-controller races, and whether a
  privileged master can issue decommission during leader failover.
- **Actual fencing:** a deployment/verifiable network or host isolation
  action; remote leases and outstanding commands must be revoked or
  allowed to expire before any replacement is activated. A database
  boolean or `--physically-fenced` claim alone is insufficient.
- **Durable evidence:** preserve both core journal and anchor, latest
  Control store/boot/high-water marks, signed operation IDs, grants,
  receipts, and an immutable incident record. Never fabricate `APPLIED`
  for an interrupted INSTALLING or RETIRING.
- **Fresh security identity:** new executor/node credential, independent
  core incarnation, new store identity and cryptographic keys. Do not
  reset the old store, import an uncertain live user, reuse a retired
  effective VLESS UUID, or bypass monotonic generations.
- **Paid rights and accounting:** preserve entitlement balances, all
  already occupied owner/device slots and accounting under the original
  ledger. Transfer/release requires separately authorized and proven
  fencing, not just deleting a technical VLESS user.
- **New node onboarding:** separate signed registration, configuration
  integrity check, fresh leases, health readiness, network admission,
  provisioned JWT/mTLS identities, safe rollback, and no overlapping
  old/new active ownership.
- **HA and UI contract:** master loss must not allow two control leaders
  or simultaneous replacements. The UI should expose incident evidence,
  approval and state progression, but must not mutate node state directly.

### Required cross-repository acceptance

1. Crash before AddUser; crash after AddUser but before INSTALLED;
   crash after INSTALLED but before Control ACK.
2. Crash after RETIRING tombstone but before RemoveUser, and after
   removal but before Control ACK.
3. Old node unexpectedly reconnects during replacement or master
   failover: it cannot obtain fresh leases, authorizations or run an
   active data plane once externally fenced.
4. Concurrent approval/retry on two Control leaders: only one
   permanent retirement and one new provisioned identity are accepted.
5. Independent Control and ElXray high-water marks, old effective UUID
   aliases, account/owner slots, rate limits and traffic counters
   remain monotonic across migration and rollback.
6. The new replacement core is deployable and passes the full real
   two-node E2E suite; the old incident remains inspectable and
   cannot be unquarantined by editing a status flag.

## Stage-4 release gate and current status

- Positive two-core PREPARE/INSTALL/RETIRE and lost-ACK recovery were
  proven on earlier exact paired commits.
- The new managed-boot static UUID/alias/tombstone guard in ElXray is
  **not yet CI-verified** at the time this note was drafted.
- Quarantine from a crash is a conservative fail-closed state; true
  replacement/decommission is still a cross-service architecture item.
- End-to-end concurrent hot reload/fencing and final paired-head
  acceptance remain required. Keep both PRs Draft until passed.

**No automatic production opt-in, merge or VPS deployment is authorized by
this note.**
