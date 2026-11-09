# Stage 2 — managed ElXray/ElX-control security contract

**State:** implementation in paired draft PRs #20 and #21; not released until both CI suites and managed multi-process E2E pass.

## Boundary and startup

A production managed node MUST explicitly set:

```ini
Environment=ELXRAY_MODE=managed
Environment=ELXRAY_REQUIRE_CONTROL_LEASE=1
Environment=ELXRAY_POLICY_STATE=/var/lib/elxray/policy.json
Environment=ELXRAY_CONTROL_LEASE_NODE_UUID=<canonical-node-uuid>
Environment=ELXRAY_CONTROL_LEASE_PUBLIC_KEY=<Control-Ed25519-public-key-base64>
Environment=ELXRAY_CONTROL_LEASE_BINDINGS_FILE=/etc/elxray/lease-bindings.json
Environment=ELXRAY_AGENT_UID=<dedicated-non-root-uid>
Environment=ELXRAY_AGENT_GID=<dedicated-non-root-gid>
```

The private `ELXRAY_CONTROL_LEASE_BINDINGS_FILE` is a root/core-owned regular JSON file with **one entry for every locally configured subscription**, e.g.:

```json
{
  "subscription-one": {
    "resourceId": "22222222-2222-4222-8222-222222222222",
    "executorId": "33333333-3333-4333-8333-333333333333",
    "minAuthorityGeneration": 9
  },
  "subscription-two": {
    "resourceId": "55555555-5555-4555-8555-555555555555",
    "executorId": "33333333-3333-4333-8333-333333333333",
    "minAuthorityGeneration": 12
  }
}
```

This is an illustrative fixture, **not** a configuration for deployment. The binding file and immediate parent directory must be root/core-owned and not group/world-writable; no symlink file, missing subscription, duplicate resource, zero generation or noncanonical UUID is allowed. Core loads and pins this map at boot. The agent has no write access to this trust configuration. For grant epoch changes, deployment must reconcile the pinned minimum generation, persistent operation state and Control grant; blindly swapping a JSON file does not promote current authority. Durable authority/failover state migration is a separate Stage 3 obligation.

The Xray JSON config must set `policy.requireSubscription=true` and define **finite, positive** `uplinkBps` and `downlinkBps` for each subscription (upstream `0` means unlimited and is rejected for managed operation). The Commander must listen on a filesystem Unix socket such as `/run/elxray/agent.sock`; TCP, abstract Unix sockets, and the proxy-outbound Commander path are not allowed in managed mode. The socket parent is prepared by deployment and owned by the core account with no group-write or public permissions. ElXray creates socket mode 0660 with dedicated agent group and refuses to overwrite an existing pathname; deploy must safely handle lifecycle/cleanup of a stopped core's socket.

The Control *node agent* service MUST set:

```ini
Environment=ELX_AGENT_MANAGED=1
Environment=ELX_AGENT_LEASE_REQUIRED=1
Environment=ELXRAY_POLICY_SOCKET=/run/elxray/agent.sock
```

Do **not** set `ELXRAY_POLICY_LOOPBACK` for managed nodes. Run the Control node agent under the dedicated non-root agent UID/GID, separate from the core. The Control policy-service on the master uses authenticated mTLS and DB-backed grants; the local Commander authenticates the agent via Linux `SO_PEERCRED`, not metadata or localhost. A managed node on other operating systems is not supported and fails closed; pure independent upstream Xray and explicit `ELXRAY_MODE=standalone` preserve standalone behavior. An ElX-paid `requireSubscription` configuration without an explicit mode is a boot error.

## Control-signed lease v3

Only Control signs version 3 lease bytes. The canonical Ed25519 transcript, excluding the signature, is exactly:

```text
elx-control-lease-v3
<nodeId>
<resourceId>
<executorId>
<subscriptionId>
<sequence>
<notBeforeUnix>
<notAfterUnix>
<ceilingUpBytesPerSecond>
<ceilingDownBytesPerSecond>
<authorityGeneration>
```

All fields are line-separated, no final newline, canonical lower-case UUIDs. The signer's authority is the dedicated central Control lease key; the node agent cannot forge or modify a ticket. The lease *resource and executor* come from Control's trusted node manifest, **never** the node's request. Control checks its PostgreSQL `elx_rate_grants` committed rates, persisted `g.epoch`, pinned core identity, active entitlement, non-rotating core and signed FUP eligibility. It signs `authorityGeneration=g.epoch` only if the trusted manifest epoch and DB epoch match. The core requires the exact pinned subscription-local node/resource/executor and a generation at or above its configured minimum and previously accepted generation. Invalid v2, wrong signature/identity/generation, stale/replayed sequence, expired ticket and ceiling violations all deny.

The current v1 signed 88-byte **core lease acceptance evidence** remains compatible: a v3 ticket can produce this evidence only after admission is actually installed and active. That existing readback proves current core incarnation, node, expiry, ceilings and applied policy. It does not itself expose executor/resource/generation; Control must retain the authoritative grant/binding lookup for it. Extension of receipt state for stronger durable handoffs is a separate follow-up and is not implicitly proven by these bytes.

A **currently installed and verified** v3 lease is required for any managed policy re-enable or speed increase. That exact policy update is checked again against ceilings and the still-enforcing local lease; a mere successful lease-delivery RPC is not authorization. Rate decreases and disable are allowed without a new grant but do not free committed central capacity until signed barrier completion. A disabled policy cannot forward traffic; a still-valid signed lease permits Control to enable it with an authorized request. Expiration or revoked limiter state prevents re-enabling, and a later accepted fresh lease requires a fresh VPN handshake for dropped flows.

## Scope and acceptance

Stage 2 covers managed boot and caller identity, signed lease v3 and rate ceiling enforcement. It does **not** implement physical client device proof (Stage 5/6), owner fences (Stage 7), durable mutation dedup / anti-rollback of grants after restart (Stage 3), global rate allocation and leader failover (later stages), or client-facing READY status (later stage). Protect the server by systemd hardening and non-writable trusted config paths. Production unit generation is owned by `ElX-deploy` and is not implemented by this PR.

Required evidence: `go test ./common/elxsecurity ./app/policy ./app/policy/command`, `go test -race` and `go vet ./...`; Go format/protobuf checks; golden v3 transcript/signature mutation tests in **both** repos; Control tests against paired Xray branch; disposable PostgreSQL and **real two-node VLESS+SO_PEERCRED** lease outage/recovery E2E. Unrun checks or green checks that exercised `main` instead of the paired branch are not Stage 2 acceptance.
