# Stage 2 managed security — deployment contract (IN PROGRESS)

**2026-11-09** · ElXray baseline `e0d41460543024c1970a7cb0b18a27e80373f7db` · paired ElX-control branch `feat/stage2-secure-core-local-agent-20261109`.

This document describes the new **opt-in managed** hardening. It does **not** claim device admission, owner generations, executor epochs, or outage freeze are implemented. See `docs/elx/adr/0001-control-core-managed-contract.md`.

## Execution mode, no silent downgrade

Production ElXray systemd unit **must** configure:
```ini
Environment=ELXRAY_MODE=managed
Environment=ELXRAY_REQUIRE_CONTROL_LEASE=1
Environment=ELXRAY_POLICY_STATE=/var/lib/elxray/policy.json
Environment=ELXRAY_CONTROL_LEASE_NODE_UUID=<canonical-node-uuid>
Environment=ELXRAY_CONTROL_LEASE_PUBLIC_KEY=<Control-Ed25519-base64-public-key>
Environment=ELXRAY_AGENT_UID=<dedicated-agent-uid>
Environment=ELXRAY_AGENT_GID=<dedicated-agent-primary-gid>
```
Technical configuration requires `policy.requireSubscription=true`, nonempty `policy.subscriptions` and configured Commander service listening on a **filesystem Unix socket**, e.g. `/run/elxray/agent.sock`. The parent directory must exist before boot, be owned by the ElXray process account, not be group-writable, and not grant access to other users. The agent must have a **different non-root UID** and configured primary GID. The socket is created by ElXray with mode 0660 and agent group. A pre-existing pathname causes startup failure: do not run two competing cores on the same socket. Do not make the directory world-writable or accept abstract sockets.

On the ElX-control agent service, configure:
```ini
Environment=ELX_AGENT_MANAGED=1
Environment=ELX_AGENT_LEASE_REQUIRED=1
Environment=ELXRAY_POLICY_SOCKET=/run/elxray/agent.sock
```
`ELXRAY_POLICY_LOOPBACK` must be **unset**. Disable any unmanaged Commander TCP listener in the production technical config. Run agent service under `ELXRAY_AGENT_UID:GID` as distinct OS user; local files and state remain owned by core user. Deploy unit composition and identity provisioning are **not** implemented in ElX-deploy yet: before production promotion, add systemd hardening, secure RuntimeDirectory and dedicated user/group provisioning there.

If `ELXRAY_MODE=managed` is present but Control lease flag, pinned signer, node UUID, durable store, valid subscriptions, or agent OS identity is absent, core refuses to initialise. A partially configured managed identity may not silently become standalone. Pure upstream Xray with no ElX environment remains standalone; `ELXRAY_MODE=standalone` is a supported explicit independent mode. **Caveat:** bare legacy `policy.subscriptions` in a manually maintained standalone config is not by itself a cryptographically signed managed manifest. The target durable authority identity/boot manifest is still Stage 3.

## Exact security boundaries

- The local gRPC server uses `SO_PEERCRED` on Linux Unix sockets. Only the configured distinct agent UID+primary GID can handshake. gRPC metadata, TCP loopback and a Unix address string are not caller credentials. Managed is unavailable on other OS; standalone is unchanged.
- `UpdateSubscription` rejects enabling or increasing either direction without a *currently accepted and still enforcing* Control-signed lease. Every increase is checked against the **accepted** ticket ceilings at application time; lease sequence, node and expiry must match. A stale ticket cannot authorize a late raise.
- Safe reductions and disabled-without-increase operations remain possible when Control is unreachable; but they do not reopen expired flows. Managed zero rate is forbidden, not unlimited. Ordinary positive-rate reduction is not a signed release barrier.
- Current Control lease transcript is `elx-control-lease-v2`, containing node+subscription+sequence+expires+ceilings. **It does not bind executor/resource/authorityGeneration. This is a remaining Stage 2 P0 and requires an inter-repo signed v3 grant/lease migration before this stage may be marked DONE.**
- Existing standalone Commander may still be accessible via local TCP, only for explicitly non-managed use. Protect it by deployment policy. Any child/owner flow enforcement remains Stage 5–9.

## Required tests

`go test ./common/elxsecurity ./app/commander ./app/policy ./app/policy/command -count=1`, `go test -race ...`, `go vet ...`, CI full formatting/proto/static checks, plus negative Linux separate-user test. See newly added `managed_security*_test.go` files. **No production readiness claim** until corresponding GitHub checks and Control agent tests PASS, and Stage 2's signed authority generation requirement is addressed.
