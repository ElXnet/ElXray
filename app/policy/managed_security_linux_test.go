//go:build linux

package policy

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common/elxjournal"
	"github.com/xtls/xray-core/common/subscriptionrate"
)

func newManagedTestPolicy(t *testing.T) (*Instance, ed25519.PrivateKey, uuid.UUID) {
	t.Helper()
	pub, signer, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, coreKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	node := uuid.New()
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(`{"Version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".key", []byte(hex.EncodeToString(coreKey.Seed())), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ELXRAY_MODE", "managed")
	t.Setenv("ELXRAY_REQUIRE_CONTROL_LEASE", "1")
	t.Setenv("ELXRAY_POLICY_STATE", path)
	journalPath := path + ".ops"
	if err := elxjournal.Provision(journalPath, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ELXRAY_OP_JOURNAL", journalPath)
	t.Setenv("ELXRAY_CONTROL_LEASE_PUBLIC_KEY", base64.StdEncoding.EncodeToString(pub))
	t.Setenv("ELXRAY_CONTROL_LEASE_NODE_UUID", node.String())
	resource := uuid.New()
	executor := uuid.New()
	bindings := filepath.Join(t.TempDir(), "bindings.json")
	encoded, err := json.Marshal(map[string]rawLeaseBinding{
		"lab": {ResourceID: resource.String(), ExecutorID: executor.String(), MinAuthorityGeneration: 8},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bindings, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ELXRAY_CONTROL_LEASE_BINDINGS_FILE", bindings)
	t.Setenv("ELXRAY_AGENT_UID", strconv.Itoa(os.Geteuid()+42))
	t.Setenv("ELXRAY_AGENT_GID", "65534")
	m, err := New(context.Background(), &Config{RequireSubscription: true, Subscriptions: map[string]*SubscriptionPolicy{
		"lab": {Emails: []string{"user"}, UplinkBps: 100, DownlinkBps: 200, Revision: 1},
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m, signer, node
}

func TestManagedRatesRejectUnsignedRaiseBetweenLeaseRenewals(t *testing.T) {
	m, signer, node := newManagedTestPolicy(t)
	limit := m.ForEmail("user")
	if err := limit.Uplink.WaitN(context.Background(), 1); !errors.Is(err, subscriptionrate.ErrDisabled) {
		t.Fatalf("managed flow opened without lease: %v", err)
	}
	mk := func(rev, up, down uint64, disabled bool) subscriptionrate.Update {
		return subscriptionrate.Update{ID: "lab", ExpectedRevision: rev, Revision: rev + 1, UplinkBps: up, DownlinkBps: down, Disabled: disabled}
	}
	if _, err := m.UpdateSubscription(mk(1, 101, 200, false)); !errors.Is(err, subscriptionrate.ErrUnauthorized) {
		t.Fatalf("missing lease allowed rate increase: %v", err)
	}
	now := time.Now().Unix()
	ticket := ControlLease{
		Version: 3, NodeID: node, ResourceID: m.leaseBindings["lab"].ResourceID, ExecutorID: m.leaseBindings["lab"].ExecutorID,
		AuthorityGeneration: 8, Subscription: "lab", Sequence: 1,
		NotBefore: now, NotAfter: now + 15, CeilingUp: 100, CeilingDown: 200,
	}
	ticket.Signature = ed25519.Sign(signer, ControlLeaseTranscript(ticket))
	if err := m.RenewControlLease(ticket); err != nil {
		t.Fatal(err)
	}
	for _, updown := range [][2]uint64{{101, 200}, {100, 201}, {101, 201}, {0, 200}} {
		if _, err := m.UpdateSubscription(mk(1, updown[0], updown[1], false)); !errors.Is(err, subscriptionrate.ErrUnauthorized) {
			t.Fatalf("in-lease ceiling exceeded for %v: %v", updown, err)
		}
	}
	for _, mutate := range []func(*ControlLease){
		func(x *ControlLease) { x.ResourceID = uuid.New() },
		func(x *ControlLease) { x.ExecutorID = uuid.New() },
		func(x *ControlLease) { x.AuthorityGeneration = 7 },
		func(x *ControlLease) { x.Version = 2 },
	} {
		invalid := ticket
		invalid.Sequence = 2
		mutate(&invalid)
		invalid.Signature = ed25519.Sign(signer, ControlLeaseTranscript(invalid))
		if err := m.RenewControlLease(invalid); err == nil {
			t.Fatalf("accepted foreign or stale signed authority: %+v", invalid)
		}
	}
	p, err := m.GetSubscription("lab")
	if err != nil || p.Revision != 1 || p.UplinkBps != 100 || p.DownlinkBps != 200 {
		t.Fatalf("rejected update corrupted state: %+v %v", p, err)
	}
	if _, err := m.UpdateSubscription(mk(1, 90, 180, false)); err != nil {
		t.Fatal("reduction:", err)
	}
	if _, err := m.UpdateSubscription(mk(2, 100, 200, false)); err != nil {
		t.Fatal("in-ceiling raise:", err)
	}
	if _, err := m.UpdateSubscription(mk(3, 100, 200, true)); err != nil {
		t.Fatal("emergency deny:", err)
	}
	if _, err := m.UpdateSubscription(mk(4, 101, 200, true)); !errors.Is(err, subscriptionrate.ErrUnauthorized) {
		t.Fatal("disabled state concealed extra allocated rate:", err)
	}
	// A disabled subscription may be enabled only within its still-live,
	// already accepted signed v3 ceiling. Disable itself never admits flows.
	if err := limit.Downlink.WaitN(context.Background(), 1); !errors.Is(err, subscriptionrate.ErrDisabled) {
		t.Fatal("disabled policy transmitted traffic:", err)
	}
	if _, err := m.UpdateSubscription(mk(4, 100, 200, false)); err != nil {
		t.Fatal("in-ceiling re-enable under signed lease rejected:", err)
	}
	if err := limit.Downlink.WaitN(context.Background(), 1); err != nil {
		t.Fatal("re-enabled signed flow still denied:", err)
	}
	// Losing the enforcement lease cannot be bypassed by incrementing the
	// revision under an older, still-signed but no longer installed ticket.
	limit.RequireLease()
	if _, err := m.UpdateSubscription(mk(5, 101, 200, false)); !errors.Is(err, subscriptionrate.ErrUnauthorized) {
		t.Fatalf("rate increased after lease was invalidated: %v", err)
	}
}

func TestManagedBootRejectsMissingModeAndLeaseFlag(t *testing.T) {
	if _, err := New(context.Background(), &Config{
		RequireSubscription: true,
		Subscriptions: map[string]*SubscriptionPolicy{"lab": {Emails: []string{"member"}, UplinkBps: 1, DownlinkBps: 1}},
	}); err == nil {
		t.Fatal("managed subscriptions started without an explicit execution mode")
	}
	t.Setenv("ELXRAY_MODE", "")
	t.Setenv("ELXRAY_REQUIRE_CONTROL_LEASE", "1")
	if _, err := New(context.Background(), &Config{}); err == nil {
		t.Fatal("partial managed environment fell back to standalone")
	}
	t.Setenv("ELXRAY_MODE", "managed")
	t.Setenv("ELXRAY_REQUIRE_CONTROL_LEASE", "")
	if _, err := New(context.Background(), &Config{}); err == nil {
		t.Fatal("managed mode without mandatory lease flag started")
	}
	t.Setenv("ELXRAY_MODE", "invalid")
	if _, err := New(context.Background(), &Config{}); err == nil {
		t.Fatal("unknown execution mode started")
	}
}

func TestManagedStartupRejectsUnlimitedEvenWithValidIdentity(t *testing.T) {
	newManagedTestPolicy(t)
	for _, rates := range [][2]uint64{{0, 200}, {100, 0}, {0, 0}} {
		_, err := New(context.Background(), &Config{RequireSubscription: true, Subscriptions: map[string]*SubscriptionPolicy{
			"lab": {Emails: []string{"member"}, UplinkBps: rates[0], DownlinkBps: rates[1]},
		}})
		if err == nil {
			t.Fatalf("managed zero/unlimited startup accepted rates: %v", rates)
		}
	}
}

func TestManagedLeaseHighWaterIsDurableAcrossRestart(t *testing.T) {
	m, signer, node := newManagedTestPolicy(t)
	binding := m.leaseBindings["lab"]
	now := time.Now().Unix()
	lease := ControlLease{
		Version: 3, NodeID: node, ResourceID: binding.ResourceID,
		ExecutorID: binding.ExecutorID, AuthorityGeneration: 8,
		Subscription: "lab", Sequence: 100,
		NotBefore: now, NotAfter: now + 15, CeilingUp: 100, CeilingDown: 200,
	}
	lease.Signature = ed25519.Sign(signer, ControlLeaseTranscript(lease))
	if err := m.RenewControlLease(lease); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{RequireSubscription: true, Subscriptions: map[string]*SubscriptionPolicy{
		"lab": {Emails: []string{"user"}, UplinkBps: 100, DownlinkBps: 200, Revision: 1},
	}}
	restarted, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if err := restarted.RenewControlLease(lease); err == nil {
		t.Fatal("accepted previously signed Control sequence after core restart")
	}
	lease.Sequence = 101
	lease.NotAfter = now + 16
	lease.Signature = ed25519.Sign(signer, ControlLeaseTranscript(lease))
	if err := restarted.RenewControlLease(lease); err != nil {
		t.Fatalf("fresh signed v3 lease after restart rejected: %v", err)
	}
}

func TestManagedCorruptJournalCannotStart(t *testing.T) {
	m, _, _ := newManagedTestPolicy(t)
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	path := os.Getenv("ELXRAY_OP_JOURNAL")
	if err := os.WriteFile(path+".anchor", []byte("torn"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(context.Background(), &Config{RequireSubscription: true, Subscriptions: map[string]*SubscriptionPolicy{
		"lab": {Emails: []string{"user"}, UplinkBps: 100, DownlinkBps: 200, Revision: 1},
	}}); err == nil {
		t.Fatal("corrupt durable operation watermark silently reopened paid node")
	}
}
