# ElXray — UUID + HWID device identity groundwork

**Status: IN_PROGRESS (first slice only).** Started 2026-11-12 in
`feat/device-identification-uuid-hwid-20261112`, based on the separate,
still-unmerged ElXray technical-provisioning branch at
`1082e66d2deab5991f68571d0d59cc78426c0251`.
Do not alter or merge the Stage-4 Draft PR while it is being tested.

## Accepted product decision

The practical device identifier is **authenticated VLESS UUID + supported
client-supplied HWID**. No separate per-device cryptographic key, additional
device certificate, challenge-response or hardware attestation is introduced.
This is a deliberately simplified threat model: a modified client may copy
or spoof its HWID. Neither UUID+HWID alone proves paid rights.

## Implemented in this first slice

- `common/elxdevice`: deterministic pair-key parser. The
  UUID is canonicalized to 16 bytes, and a bounded opaque, case-sensitive
  HWID is represented by a profile-scoped, domain-separated SHA-256
  correlation fingerprint. The raw HWID is not retained.
- Per-node, in-memory registry of **already authorized and authenticated**
  connections. Two concurrent connections using the same UUID+HWID count
  as one active device. Different HWIDs remain different devices. Releases
  are idempotent and races with reconnect are protected by a mutex.
- A revoked pair cannot be re-observed in the registry instance. Denial
  returns stop callbacks without executing them under the registry lock.
  Persist any production revocation in the policy layer **before** calling
  the callbacks. Persisted denials can be restored when the core starts.
- `cmd/elx-device-demo`: bounded Go JSON prototype that
  renders a local device identifier/fingerprint and explicitly reports
  `payloadAuthorized=false`. This is **not a real VLESS
  protocol client**, and never sends credentials or permits VPN traffic.
- No dependency on device-signing keys, cloud attestation or a new
  transport encryption layer.

## Why this is NOT yet integrated into active VLESS traffic

Stock VLESS authenticates a profile UUID; it does **not** deliver a
hardware identifier to the server. It would be misleading to count
distinct physical devices from a UUID, IP address, TLS fingerprint or
a client-chosen header alone. No profile is admitted by this module.

The architecture handoff already tracks this as **AX-006**. Before wiring
the observer to a real VPN flow, the architecture must specify the
minimal supported-client HWID delivery syntax, bounds and replay behavior,
what happens to third-party clients without HWID, and the Control-owned
per-user slot/deny/policy generation contract. These are cross-component
interfaces, not permission to implement major ElX-control changes here.

The current device registry is intentionally *non-authorizing*. It is
not the central paid-device slot counter, has no signed Control
operation, and does not persist revocations by itself. Stage-4
technical profiles remain non-admitting until a separately authorized
user/device session is available.

## Verification

The packages have no new external dependencies. The development
snapshot was locally checked in a matching minimal module with Go
1.23:

`go test -race -count=1 ./common/elxdevice ./cmd/elx-device-demo`

Result **PASS** (6 tests), including reconnection, revocation, collision
and concurrent observation. This is **not** evidence of a full Go 1.27
ElXray build, real XHTTP/REALITY connection or cross-node PostgreSQL
integration. Full repository CI remains pending once pushed.

## Stage boundary

Stage 5: define and prototype the UUID+HWID representation and
observation path, then demonstrate hardware ID delivery on a
real supported Go protocol client when the minimal wire contract is
agreed. Stage 6/data-plane integration: apply Control-owned device/slot
authorization to actual VPN flows and enforce cross-node revocation.
Do not widen Stage 4 retroactively.

**Security invariant:** device correlation is not admission. All
unauthorized VLESS payload still fails closed.
