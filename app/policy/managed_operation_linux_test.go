//go:build linux

package policy

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common/elxjournal"
	"github.com/xtls/xray-core/common/subscriptionrate"
)

func testManagedOperation(m *Instance, node uuid.UUID, id string, update subscriptionrate.Update) elxjournal.Command {
	binding := m.leaseBindings["lab"]
	return elxjournal.Command{
		OperationID: id, NodeID: node.String(),
		ExecutorID: binding.ExecutorID.String(), ResourceID: binding.ResourceID.String(),
		AuthorityGeneration: 8, ExpectedRevision: update.ExpectedRevision,
		NewRevision: update.Revision, PayloadSHA256: ManagedUpdateHash(update), Kind: "set-rate",
	}
}

func TestDurableManagedOperationApplyDedupAndRestart(t *testing.T) {
	m, signer, node := newManagedTestPolicyWithJournal(t)
	binding := m.leaseBindings["lab"]
	now := time.Now().Unix()
	lease := ControlLease{
		Version: 3, NodeID: node, ResourceID: binding.ResourceID, ExecutorID: binding.ExecutorID,
		AuthorityGeneration: 8, Subscription: "lab", Sequence: 1, NotBefore: now,
		NotAfter: now + 15, CeilingUp: 100, CeilingDown: 200,
	}
	lease.Signature = ed25519.Sign(signer, ControlLeaseTranscript(lease))
	if err := m.RenewControlLease(lease); err != nil {
		t.Fatal(err)
	}
	update := subscriptionrate.Update{ID: "lab", ExpectedRevision: 1, Revision: 2, UplinkBps: 90, DownlinkBps: 180}
	cmd := testManagedOperation(m, node, uuid.NewString(), update)
	if _, err := m.UpdateSubscription(update); !errors.Is(err, subscriptionrate.ErrUnauthorized) {
		t.Fatalf("unattributed managed operation bypassed journal: %v", err)
	}
	bad := cmd
	bad.ResourceID = uuid.NewString()
	if _, err := m.UpdateManagedSubscription(update, bad); !errors.Is(err, subscriptionrate.ErrUnauthorized) {
		t.Fatalf("wrong resource applied: %v", err)
	}
	bad = cmd
	bad.PayloadSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if _, err := m.UpdateManagedSubscription(update, bad); !errors.Is(err, subscriptionrate.ErrUnauthorized) {
		t.Fatalf("incorrect payload hash applied: %v", err)
	}
	p, err := m.UpdateManagedSubscription(update, cmd)
	if err != nil || p.Revision != 2 || p.UplinkBps != 90 {
		t.Fatalf("exact Control operation failed: %+v %v", p, err)
	}
	if proof, err := m.DurablePolicyProof(p, "stage3-claim"); err != nil || len(proof) != ed25519.SignatureSize {
		t.Fatalf("applied durable policy proof unavailable: %v", err)
	}
	if p, err = m.UpdateManagedSubscription(update, cmd); err != nil || p.Revision != 2 {
		t.Fatalf("same operation retry changed state: %+v %v", p, err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	m, err = New(context.Background(), &Config{RequireSubscription: true, Subscriptions: map[string]*SubscriptionPolicy{
		"lab": {Emails: []string{"user"}, UplinkBps: 100, DownlinkBps: 200, Revision: 1},
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if p, err := m.UpdateManagedSubscription(update, cmd); err != nil || p.Revision != 2 {
		t.Fatalf("applied command lost over restart: %+v %v", p, err)
	}
	changed := cmd
	changed.PayloadSHA256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if _, err := m.opJournal.Begin(changed); !errors.Is(err, elxjournal.ErrCollision) {
		t.Fatalf("operation ID reuse accepted: %v", err)
	}
	stale := update
	stale.ExpectedRevision, stale.Revision = 1, 2
	stale.UplinkBps = 95
	if _, err := m.UpdateManagedSubscription(stale, testManagedOperation(m, node, uuid.NewString(), stale)); !errors.Is(err, subscriptionrate.ErrConflict) {
		t.Fatalf("stale managed CAS accepted: %v", err)
	}
}

func TestPendingManagedIntentBlocksBootAndLease(t *testing.T) {
	m, _, node := newManagedTestPolicyWithJournal(t)
	u := subscriptionrate.Update{ID: "lab", ExpectedRevision: 1, Revision: 2, UplinkBps: 90, DownlinkBps: 180}
	cmd := testManagedOperation(m, node, uuid.NewString(), u)
	if _, err := m.opJournal.Begin(cmd); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := New(context.Background(), &Config{RequireSubscription: true, Subscriptions: map[string]*SubscriptionPolicy{
		"lab": {Emails: []string{"user"}, UplinkBps: 100, DownlinkBps: 200, Revision: 1},
	}}); !errors.Is(err, elxjournal.ErrUncertain) {
		t.Fatalf("unresolved mutation restarted as active service: %v", err)
	}
}
