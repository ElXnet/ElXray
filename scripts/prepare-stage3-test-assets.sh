#!/usr/bin/env bash
# Stage-3 local geodata fixtures. Mirrors .github/actions/prepare-assets.
# Verification is mandatory: never use unverified generated or cached .dat.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
command -v curl >/dev/null || { echo 'curl is required' >&2; exit 2; }
command -v sha256sum >/dev/null || { echo 'sha256sum is required' >&2; exit 2; }
mkdir -p resources

verify() {
    local data="$1" checksum="$2" digest
    digest="$(awk 'NR == 1 {print $1}' "$checksum")"
    [[ "$digest" =~ ^[a-fA-F0-9]{64}$ ]] || {
        echo "Invalid checksum format: $checksum" >&2
        return 1
    }
    printf '%s  %s\n' "$digest" "$data" | sha256sum --check -
}

for item in 'geoip/geoip-lite geoip' 'geosite/geosite geosite'; do
    read -r remote local <<< "$item"
    data="resources/${local}.dat"
    checksum="resources/${local}.sha256sum"
    if [[ -s "$data" && -s "$checksum" ]]; then
        verify "$data" "$checksum" || {
            echo "Untrusted existing geodata: $data. Do not run full tests." >&2
            exit 1
        }
        continue
    fi
    tmp="$(mktemp -d "$root/resources/.stage3-assets.XXXXXXXX")"
    cleanup() { rm -rf "$tmp"; }
    trap cleanup EXIT
    base="https://raw.githubusercontent.com/XTLS/Xray-rules-dat/release/${remote}.dat"
    curl --fail --location --retry 3 --connect-timeout 15 --max-time 120 "$base" -o "$tmp/${local}.dat"
    curl --fail --location --retry 3 --connect-timeout 15 --max-time 120 "${base}.sha256sum" -o "$tmp/${local}.sha256sum"
    verify "$tmp/${local}.dat" "$tmp/${local}.sha256sum"
    install -m 0644 "$tmp/${local}.dat" "$data"
    install -m 0644 "$tmp/${local}.sha256sum" "$checksum"
    cleanup
    trap - EXIT
done
echo "PASS: checksum-verified ElXray geodata fixtures match the GitHub CI asset sources"
