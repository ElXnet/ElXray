# Offline Stage-4 technical incident inspection

This **read-only** utility is for a node isolated after a crash during the
durable `INSTALLING` or `RETIRING` window. It does not repair an uncertain
data-plane result, produce a Control APPLIED receipt, reset a paid slot or
authorize a replacement UUID. Never replay expired INSTALL/RETIRE tickets.

1. Disconnect the affected node from public listeners and prevent a second
   ElXray instance from starting. Preserve both the journal and `.anchor`
   and the independent PostgreSQL Control witness before any administrative
   action; perform inspection on an isolated copy when possible.
2. Retrieve the exact profile and signed operation ID via Control's
   `inspect-technical-recovery` read-only command. Retrieve the expected
   `store_id` from the **independent** Control database, not from the node.
3. Run `go run ./cmd/elx-technical-inspect -journal /ABS/PATH/operations.json
   -policy-state /ABS/PATH/policy.json -expect-store STORE_UUID -profile PROFILE_UUID -operation OP_UUID`.
   Output contains only IDs, journal phase, authority/revision, denial
   generation and `requiresIsolation`, never user email/credentials.
   Run with `-require-terminal` as a fail-closed deployment gate.
4. `INSTALLING` means AddUser may or may not have happened. `RETIRING`
   means a durable permanent UUID tombstone exists, but user removal may
   not have completed. Both remain **quarantined**: no local utility is
   permitted to mark INSTALLED/RETIRED or authorize VPN payload.
5. If evidence cannot establish the exact signed completed outcome, preserve
   the Control INTENT and paid reservations. Replacement requires separately
   authorized decommission/rebootstrap of a new core/store and inventory
   reconciliation; neither the old UUID nor its normalized VLESS aliases may
   be reused. Do **not** manually edit the signed journal or PostgreSQL rows.

This tool is *inspection*, not a signed operator reconciliation protocol.
A complete, independently attested abort/quarantine confirmation that can
safely close PostgreSQL INTENT remains a release blocker for Stage 4.

The inspector acquires the exact managed policy state's exclusive `.lock`
using nonblocking Unix flock. It refuses a missing lock, an active core, or
an unsupported platform rather than inspecting a concurrently mutating
journal. It closes the descriptor without modifying policy, journal or anchor.
