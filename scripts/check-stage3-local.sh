#!/usr/bin/env bash
# ElX stage-3 verification. Runs in a real checked-out pair of repositories.
# No GitHub Actions required. Fetches only checksum-verified test assets; does not touch live policy or database.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
control="${ELX_CONTROL_DIR:-}"
if [[ -z "$control" ]]; then
  control="$(cd "$root/../ElX-control" 2>/dev/null && pwd || true)"
fi
echo "ElXray HEAD: $(git -C "$root" rev-parse HEAD 2>/dev/null || echo unknown)"
echo "Go toolchain: $(cd "$root" && go version)"
if [[ ! -d "$control" || ! -f "$control/go.mod" ]]; then
  echo "ERROR: set ELX_CONTROL_DIR to a checked-out ElX-control source tree" >&2
  exit 2
fi
echo "Control HEAD: $(git -C "$control" rev-parse HEAD 2>/dev/null || echo unknown)"
required="$(awk '/^go [0-9]+\.[0-9]+/{print $2;exit}' "$root/go.mod")"
if [[ -z "$required" ]]; then
  echo "ERROR: core go.mod missing Go requirement" >&2;exit 2
fi
current="$(cd "$root" && go version | sed -n 's/.*go\([0-9]*\)\.\([0-9]*\).*/\1 \2/p')"
read -r major minor <<< "$current"
req_major="${required%%.*}"
req_minor="${required#*.}"
req_minor="${req_minor%%.*}"
if (( major < req_major || (major == req_major && minor < req_minor) )); then
  echo "ERROR: Go $required or newer required; local $(go version) is not a full-repo test environment" >&2
  exit 2
fi

check_format() {
  local repo="$1"
  local bad
  bad="$(cd "$repo"; git diff --name-only --diff-filter=ACMR main...HEAD -- '*.go' | xargs -r gofmt -l)"
  if [[ -n "$bad" ]]; then
    echo "FAIL: gofmt differences ($repo):" >&2
    echo "$bad" >&2
    return 1
  fi
}
echo "[1/8] core Go 1.27 gofumpt formatting — same as CI"
(cd "$root"; go run ./infra/vformat/main.go -mode check)
echo "[2/8] Control gofmt formatting"
check_format "$control"
echo "[3/8] core focused/race"
(cd "$root"; go test -count=1 -race ./common/elxjournal ./common/subscriptionrate ./app/policy ./app/policy/command)
if [[ "${ELX_STAGE3_FAST:-0}" == "1" ]]; then
  echo "FAST MODE: focused race suites + vet; full test suite is NOT RUN."
  (cd "$root"; go vet ./...)
  (cd "$control"; go test -count=1 -race ./internal/elxcontrol/journal ./internal/elxcontrol/policytransport ./internal/elxcontrol/corepolicy ./cmd/elx-control; go vet ./...)
  echo "LOCAL FOCUSED CHECKS PASS; full repository/E2E NOT RUN (ELX_STAGE3_FAST=1)"
  exit 0
fi
echo "[4/8] download/verify test geodata (identical to CI)"
bash "$root/scripts/prepare-stage3-test-assets.sh"
echo "[5/8] core repository-wide suite and static analysis"
if [[ "${ELX_EXTERNAL_NETWORK_TESTS:-0}" == "1" ]]; then
  echo "EXTERNAL NETWORK ON: including live DNS/ECH/REALITY tests"
  (cd "$root"; go test -count=1 -timeout 30m ./...; go vet ./...)
else
  # Keep this list byte-for-byte aligned with Control's
  # scripts/elxray-full-go-tests.sh, our CI deterministic regression.
  skip='^(TestECHDial|TestDOHNameServer.*|TestQUICNameServer.*|TestTCPLocalNameServer.*|TestLocalNameServer|TestVlessXtlsVisionReality|TestVlessRealityFingerprints)$'
  echo "NETWORK TESTS NOT RUN (explicit opt-in: ELX_EXTERNAL_NETWORK_TESTS=1)"
  echo "Excluded test regex: $skip"
  (cd "$root"; go test -count=1 -timeout 30m -skip "$skip" ./...; go vet ./...)
fi

echo "[6/8] Control focused/race"
(cd "$control"; go test -count=1 -race ./internal/elxcontrol/journal ./internal/elxcontrol/policytransport ./internal/elxcontrol/corepolicy ./cmd/elx-control)
echo "[7/8] Control repository-wide suite and static analysis"
(cd "$control"; go test -count=1 ./...; go vet ./...)

echo "[8/8] PostgreSQL integration coverage"
if [[ -z "${ELX_TEST_POSTGRES_DSN:-}" ]]; then
  echo "NOT RUN: PostgreSQL integration tests (set ELX_TEST_POSTGRES_DSN to an isolated non-production PostgreSQL database)"
else
  echo "PostgreSQL DSN supplied; verify the actual DB-backed tests were run (not skipped) in the log."
fi
echo "NOTE: external-network tests remain NOT RUN unless ELX_EXTERNAL_NETWORK_TESTS=1."
echo "NOTE: this script does not replace the two-node/partition/crash E2E suite in ElX-control."
echo "PASS: all test commands executed by check-stage3-local.sh succeeded"
