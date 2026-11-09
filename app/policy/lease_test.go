//go:build linux

package policy

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common/subscriptionrate"
)

func TestSignedControlLeaseRequiresNodeAndAbsoluteExpiry(t *testing.T) {
	t.Setenv("ELXRAY_MODE", "managed")
	t.Setenv("ELXRAY_AGENT_UID", fmt.Sprint(os.Geteuid()+100))
	t.Setenv("ELXRAY_AGENT_GID", "65534")
	pub, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	node := uuid.New()
	state := filepath.Join(t.TempDir(), "policy.json")
	_, coreKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(state, []byte("{\"Version\":1}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(state+".key", []byte(hex.EncodeToString(coreKey.Seed())), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ELXRAY_POLICY_STATE", state)
	t.Setenv("ELXRAY_REQUIRE_CONTROL_LEASE", "1")
	t.Setenv("ELXRAY_CONTROL_LEASE_PUBLIC_KEY", base64.StdEncoding.EncodeToString(pub))
	t.Setenv("ELXRAY_CONTROL_LEASE_NODE_UUID", node.String())
	resource := uuid.New()
	executor := uuid.New()
	bindings := filepath.Join(t.TempDir(), "bindings.json")
	if err := os.WriteFile(bindings, []byte(fmt.Sprintf(`{"lab":{"resourceId":%q,"executorId":%q,"minAuthorityGeneration":7}}`, resource.String(), executor.String())), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ELXRAY_CONTROL_LEASE_BINDINGS_FILE", bindings)
	m, err := New(context.Background(), &Config{
		RequireSubscription: true,
		Subscriptions: map[string]*SubscriptionPolicy{
			"lab": {Emails: []string{"member"}, UplinkBps: 100, DownlinkBps: 200},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	limit := m.ForEmail("member")
	if limit == nil {
		t.Fatal("missing budget")
	}
	if err := limit.Downlink.WaitN(context.Background(), 1); !errors.Is(err, subscriptionrate.ErrDisabled) {
		t.Fatal("unleased subscription was active:", err)
	}
	now := time.Now().Unix()
	ticket := ControlLease{
		Version: 3, NodeID: node, ResourceID: resource, ExecutorID: executor,
		AuthorityGeneration: 7, Subscription: "lab", Sequence: 1,
		NotBefore: now, NotAfter: now + 15, CeilingUp: 100, CeilingDown: 200,
	}
	sign := func(tick ControlLease) ControlLease {
		tick.Signature = ed25519.Sign(key, ControlLeaseTranscript(tick))
		return tick
	}
	// Preserve the valid authority/binding in each negative case. Only one
	// property is changed, so rejection is attributable to that field.
	invalid := []ControlLease{}
	for _, mutate := range []func(*ControlLease){
		func(x *ControlLease) { x.Version = 0 },
		func(x *ControlLease) { x.NodeID = uuid.New() },
		func(x *ControlLease) { x.ResourceID = uuid.New() },
		func(x *ControlLease) { x.ExecutorID = uuid.New() },
		func(x *ControlLease) { x.AuthorityGeneration = 6 },
		func(x *ControlLease) { x.Subscription = "other" },
		func(x *ControlLease) { x.Sequence = 0 },
		func(x *ControlLease) { x.NotBefore = now + 8 },
		func(x *ControlLease) { x.NotBefore = now - 60 },
		func(x *ControlLease) { x.NotAfter = now + 120 },
		func(x *ControlLease) { x.CeilingUp = 50 },
		func(x *ControlLease) { x.CeilingDown = 80 },
	} {
		bad := ticket
		mutate(&bad)
		invalid = append(invalid, bad)
	}
	for _, bad := range invalid {
		if err := m.RenewControlLease(sign(bad)); err == nil {
			t.Fatalf("accepted invalid ticket: %+v", bad)
		}
	}
	if err := m.RenewControlLease(sign(ticket)); err != nil {
		t.Fatal(err)
	}
	cleanup, err := limit.TrackConnection(func() {})
	if err != nil {
		t.Fatal(err)
	}
	cleanup()
	if err := m.RenewControlLease(sign(ticket)); err == nil {
		t.Fatal("Control lease sequence replay accepted")
	}
	ticket.Sequence = 2
	ticket.NotAfter = now + 16
	tamper := sign(ticket)
	tamper.NotAfter = now + 25
	tamper.CeilingUp = 1000
	if err := m.RenewControlLease(tamper); err == nil {
		t.Fatal("tampered unsigned expiry accepted")
	}
	if err := m.RenewControlLease(sign(ticket)); err != nil {
		t.Fatal(err)
	}
	// Replayed old grant generation with a NEW sequence is still invalid.
	stale := ticket
	stale.Sequence = 3
	stale.AuthorityGeneration = 6
	if err := m.RenewControlLease(sign(stale)); err == nil {
		t.Fatal("old authority generation lease accepted")
	}
	nonce := "00112233445566778899aabbccddeeff"
	proof, err := m.SignedLeaseAcceptance("lab", nonce)
	if err != nil {
		t.Fatal(err)
	}
	if len(proof) != leaseAcceptanceBytes+ed25519.SignatureSize {
		t.Fatalf("malformed signed core acceptance: %d", len(proof))
	}
	data := proof[:leaseAcceptanceBytes]
	transcript := fmt.Appendf(nil, "elx-lease-accept-v1\n%x\n%x\n%x", nonce, "lab", data)
	if !ed25519.Verify(coreKey.Public().(ed25519.PublicKey),
		transcript, proof[leaseAcceptanceBytes:]) {
		t.Fatal("signed lease acceptance did not use the durable core key")
	}
	if binary.BigEndian.Uint64(data[32:40]) != 2 ||
		binary.BigEndian.Uint64(data[40:48]) != uint64(ticket.NotAfter) ||
		binary.BigEndian.Uint64(data[48:56]) != 100 ||
		binary.BigEndian.Uint64(data[56:64]) != 200 ||
		binary.BigEndian.Uint64(data[64:72]) != 1 {
		t.Fatal("signed lease proof not bound to accepted ticket and live policy")
	}
	if ed25519.Verify(coreKey.Public().(ed25519.PublicKey),
		fmt.Appendf(nil, "elx-lease-accept-v1\n%x\n%x\n%x",
			"ffeeddccbbaa99887766554433221100", "lab", data),
		proof[leaseAcceptanceBytes:]) {
		t.Fatal("core lease proof replayed with a different Control nonce")
	}
	if _, err := m.SignedLeaseAcceptance("other", nonce); err == nil {
		t.Fatal("accepted unassigned lease subscription")
	}
	_, err = m.UpdateSubscription(subscriptionrate.Update{
		ID: "lab", ExpectedRevision: 1, Revision: 2,
		UplinkBps: 100, DownlinkBps: 200, Disabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.SignedLeaseAcceptance("lab", nonce); err == nil {
		t.Fatal("disabled core signed an active lease proof")
	}
}

func TestLeaseModeRejectsMissingTrustAnchor(t *testing.T) {
	t.Setenv("ELXRAY_MODE", "managed")
	t.Setenv("ELXRAY_AGENT_UID", fmt.Sprint(os.Geteuid()+100))
	t.Setenv("ELXRAY_AGENT_GID", "65534")
	t.Setenv("ELXRAY_REQUIRE_CONTROL_LEASE", "1")
	t.Setenv("ELXRAY_CONTROL_LEASE_PUBLIC_KEY", "")
	t.Setenv("ELXRAY_CONTROL_LEASE_NODE_UUID", uuid.NewString())
	if _, err := New(context.Background(), &Config{
		RequireSubscription: true,
		Subscriptions:       map[string]*SubscriptionPolicy{"lab": {Emails: []string{"a"}}},
	}); err == nil {
		t.Fatal("mandatory lease without Control key accepted")
	}
	if _, err := New(context.Background(), &Config{
		RequireSubscription: false,
		Subscriptions:       map[string]*SubscriptionPolicy{"lab": {Emails: []string{"a"}}},
	}); err == nil {
		t.Fatal("unmanaged subscription bypassed mandatory Control lease")
	}
}
