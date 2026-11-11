# Stage-4 technical VLESS provisioning — frozen release criteria

**Scope freeze (2026-11-12).** This stage implements only technical VLESS
profile provisioning in ElXray with signed ElX-control authority. A technical
profile **never admits payload** without a separate device/owner proof.
No new Control business features, HA stack, payments, user devices, or node
decommission protocol may become a condition of this stage.

| Requirement | Acceptance evidence | Status |
| --- | --- | --- |
| Signed PREPARE, persisted journal intent | Go unit + two-real-core PostgreSQL E2E | Previously PASS |
| Signed INSTALL, actual live VLESS user, no core restart | Core-signed APPLIED + two-core E2E | Previously PASS |
| Signed RETIRE, durable UUID tombstone, traffic denied | Core-signed APPLIED + two-core E2E | Previously PASS |
| Lost ACK of INSTALL and RETIRE; expired mutation never replayed | Fault-injected two-core E2E | Previously PASS |
| Interrupted INSTALLING/RETIRING | Fail-closed durable state, no false APPLIED, offline inspection | Implemented; final regression pending |
| UUID normalization, stale static config and multi-inbound alias | Unit + real-core rejection and rollback E2E | Implemented; final regression pending |
| Concurrent hot-reload and signed mutation | Registry/policy lock ordering, no deadlock or cross-inbound alias | Implemented; final regression pending |
| Full exact-head CI and paired Control compatibility | GitHub Actions on pinned commits | Pending |

**Release gate is binary.** Fix defects within these criteria; do not invent
additional stages or silently expand the acceptance table. Operational
replacement of quarantined nodes and HA master takeover are architecture/
Deploy/Control follow-ups, not Stage-4 core provisioning release criteria.
No merge to main, deployment, or live technical payload opt-in until the
above checks are evidenced. Test-only CI failures are fixed as defects, not
counted as new project phases.
