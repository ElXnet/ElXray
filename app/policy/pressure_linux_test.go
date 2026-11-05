//go:build linux

package policy

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/xtls/xray-core/common/subscriptionrate"
)

func TestSignedPressureBindingAndPolicyRevision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	pub, signer, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"Version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".key", []byte(hex.EncodeToString(signer.Seed())), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ELXRAY_POLICY_STATE", path)
	m, err := New(context.Background(), &Config{RequireSubscription: true,
		Subscriptions: map[string]*SubscriptionPolicy{
			"account": {Emails: []string{"member"}, UplinkBps: 1000, DownlinkBps: 2000, Revision: 1},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	m.ForEmail("member").Uplink.RecordPayload(42)
	m.ForEmail("member").Downlink.RecordPayload(84)
	nonce := "00112233445566778899aabbccddeeff"
	first, err := m.SignedPressure("account", nonce)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != pressureEvidenceBytes+ed25519.SignatureSize {
		t.Fatalf("unexpected sample size: %d", len(first))
	}
	data := first[:pressureEvidenceBytes]
	transcript := fmt.Appendf(nil, "elx-pressure-v1\n%x\n%x\n%x", nonce, "account", data)
	if !ed25519.Verify(pub, transcript, first[pressureEvidenceBytes:]) {
		t.Fatal("pressure signature was not bound to the nonce and subscription")
	}
	if ed25519.Verify(pub, fmt.Appendf(nil, "elx-pressure-v1\n%x\n%x\n%x",
		"ffeeddccbbaa99887766554433221100", "account", data), first[pressureEvidenceBytes:]) {
		t.Fatal("accepted replay with another challenge")
	}
	if ed25519.Verify(pub, fmt.Appendf(nil, "elx-pressure-v1\n%x\n%x\n%x",
		nonce, "someone-else", data), first[pressureEvidenceBytes:]) {
		t.Fatal("accepted another subscription")
	}
	if got := binary.BigEndian.Uint64(data[32:40]); got != 1 {
		t.Fatalf("wrong policy revision: %d", got)
	}
	if got := binary.BigEndian.Uint64(data[40:48]); got != 1000 {
		t.Fatalf("wrong upload policy: %d", got)
	}
	if got := binary.BigEndian.Uint64(data[48:56]); got != 2000 {
		t.Fatalf("wrong download policy: %d", got)
	}
	if got := binary.BigEndian.Uint64(data[56:64]); got != 42 {
		t.Fatalf("wrong upload payload: %d", got)
	}
	if got := binary.BigEndian.Uint64(data[88:96]); got != 84 {
		t.Fatalf("wrong download payload: %d", got)
	}
	tampered := append([]byte(nil), first...)
	tampered[64] ^= 1
	if ed25519.Verify(pub, fmt.Appendf(nil, "elx-pressure-v1\n%x\n%x\n%x",
		nonce, "account", tampered[:pressureEvidenceBytes]), tampered[pressureEvidenceBytes:]) {
		t.Fatal("signature accepted edited limiter pressure")
	}
	if _, err := m.UpdateSubscription(subscriptionrate.Update{
		ID: "account", ExpectedRevision: 1, Revision: 2,
		UplinkBps: 500, DownlinkBps: 1500,
	}); err != nil {
		t.Fatal(err)
	}
	second, err := m.SignedPressure("account", nonce)
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint64(second[16:24]) <= binary.BigEndian.Uint64(first[16:24]) ||
		binary.BigEndian.Uint64(second[32:40]) != 2 ||
		binary.BigEndian.Uint64(second[40:48]) != 500 {
		t.Fatal("sequence or durable policy revision did not advance")
	}
	for _, invalid := range []string{"", "0011", "00112233445566778899AABBCCDDEEFF", "00112233445566778899aabbccddeefg"} {
		if _, err := m.SignedPressure("account", invalid); err == nil {
			t.Fatalf("accepted malformed challenge %q", invalid)
		}
	}
	if _, err := m.SignedPressure("missing", nonce); err == nil {
		t.Fatal("signed pressure for unknown subscription")
	}
}

func TestSignedPressureRequiresDurableSigningKey(t *testing.T) {
	t.Setenv("ELXRAY_POLICY_STATE", "")
	m, err := New(context.Background(), &Config{Subscriptions: map[string]*SubscriptionPolicy{
		"account": {Emails: []string{"member"}, UplinkBps: 100, DownlinkBps: 100},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.SignedPressure("account", "00112233445566778899aabbccddeeff"); err == nil {
		t.Fatal("signed pressure without durable policy signing key")
	}
}
