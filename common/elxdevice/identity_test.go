package elxdevice

import (
	"errors"
	"strings"
	"testing"
)

const testProfile = "12345678-1234-4abc-8def-123456789abc"

func TestDeviceKeyStableAndSeparatesProfilesAndHWIDs(t *testing.T) {
	a, err := Parse(testProfile, "hwid:stable-01")
	if err != nil || !a.Valid() {
		t.Fatal(a, err)
	}
	same, err := Parse(strings.ToUpper(testProfile), "hwid:stable-01")
	if err != nil || a != same {
		t.Fatal("equivalent printed UUID changed key", err)
	}
	nextHWID, err := Parse(testProfile, "hwid:stable-02")
	if err != nil || a == nextHWID {
		t.Fatal("different HWIDs merged", err)
	}
	nextProfile, err := Parse("12345678-1234-4abc-8def-123456789abd", "hwid:stable-01")
	if err != nil || a == nextProfile || a.HWIDFingerprint() == nextProfile.HWIDFingerprint() {
		t.Fatal("different VLESS profiles merged", err)
	}
	alternateCase, err := Parse(testProfile, "HWID:stable-01")
	if err != nil || a == alternateCase {
		t.Fatal("opaque HWID case changed without contract", err)
	}
	if a.HWIDFingerprint() == "" || strings.Contains(a.HWIDFingerprint(), "stable") {
		t.Fatal("HWID fingerprint leaked plaintext")
	}
}

func TestDeviceIdentityRejectsMalformedClientInputs(t *testing.T) {
	for _, value := range []string{"", "invalid", "00000000-0000-0000-0000-000000000000", "1234567812344abc8def123456789abc", "12345678-1234-4abc-8def-123456789abz"} {
		if _, err := Parse(value, "hardware-id"); !errors.Is(err, ErrInvalidProfile) {
			t.Fatalf("invalid profile %q accepted: %v", value, err)
		}
	}
	for _, value := range []string{"", " a", "a ", "a\nb", "a\x00b", strings.Repeat("z", 257), string([]byte{0xff})} {
		if _, err := Parse(testProfile, value); !errors.Is(err, ErrInvalidHWID) {
			t.Fatalf("invalid HWID %q accepted: %v", value, err)
		}
	}
}
