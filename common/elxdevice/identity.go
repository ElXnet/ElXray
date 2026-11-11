// Package elxdevice implements local, non-authorizing device observations.
// A device is indexed by an exact VLESS profile UUID and an opaque HWID
// supplied by a supported client. Neither component proves physical device
// ownership, and this package MUST NOT enable VPN payload by itself.
package elxdevice

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	ErrInvalidProfile = errors.New("invalid canonical VLESS profile UUID")
	ErrInvalidHWID    = errors.New("invalid client HWID")
)

// Key contains no plaintext HWID. It is for correlation and in-memory
// observation, not a bearer credential or a Control-issued authorization.
// The original profile UUID is deliberately NOT VLESS-normalized: the
// authenticated profile must be checked against the exact Control binding
// before this observation is created.
type Key struct {
	Profile  [16]byte
	HWIDHash [32]byte
}

// Parse constructs a deterministic key without trusting IP, User-Agent or
// untrusted routing bytes as a substitute for HWID. HWIDs are opaque and
// case-sensitive: the client must provide a stable representation. Any wire
// format or client collection mechanism belongs in the architecture contract.
func Parse(profileUUID, hwid string) (Key, error) {
	var result Key
	if len(profileUUID) != 36 || profileUUID[8] != '-' || profileUUID[13] != '-' ||
		profileUUID[18] != '-' || profileUUID[23] != '-' {
		return result, ErrInvalidProfile
	}
	raw := strings.ReplaceAll(profileUUID, "-", "")
	if len(raw) != 32 {
		return result, ErrInvalidProfile
	}
	decoded, err := hex.DecodeString(raw)
	if err != nil || len(decoded) != 16 {
		return result, ErrInvalidProfile
	}
	copy(result.Profile[:], decoded)
	if result.Profile == [16]byte{} {
		return Key{}, ErrInvalidProfile
	}
	if len(hwid) == 0 || len(hwid) > 256 || !utf8.ValidString(hwid) ||
		strings.TrimSpace(hwid) != hwid {
		return Key{}, ErrInvalidHWID
	}
	for _, char := range hwid {
		if unicode.IsControl(char) {
			return Key{}, ErrInvalidHWID
		}
	}
	// Scope the pseudonymous fingerprint to the exact authenticated UUID.
	// The same HWID used with different profiles must not create a shared
	// cross-account identifier in telemetry or diagnostics. Neither this
	// digest nor the UUID proves physical ownership.
	h := sha256.New()
	_, _ = h.Write([]byte("elx-observed-hwid-v2\x00"))
	_, _ = h.Write(result.Profile[:])
	_, _ = h.Write([]byte(hwid))
	copy(result.HWIDHash[:], h.Sum(nil))
	return result, nil
}

func (k Key) Valid() bool {
	return k.Profile != [16]byte{} && k.HWIDHash != [32]byte{}
}

func (k Key) HWIDFingerprint() string {
	return hex.EncodeToString(k.HWIDHash[:])
}
