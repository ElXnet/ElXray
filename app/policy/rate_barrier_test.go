//go:build linux

package policy

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common/subscriptionrate"
	feature "github.com/xtls/xray-core/features/policy"
)

func TestSignedRateBarrierRequiresDurablePolicyAndQuietTransfers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{\"Version\":1}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".key", []byte(hex.EncodeToString(priv.Seed())), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ELXRAY_POLICY_STATE", path)
	m, err := New(context.Background(), &Config{
		RequireSubscription: true,
		Subscriptions: map[string]*SubscriptionPolicy{"a": {
			Emails: []string{"member"}, UplinkBps: 1000, DownlinkBps: 1000, Revision: 1,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	_, err = m.UpdateSubscription(subscriptionrate.Update{
		ID: "a", ExpectedRevision: 1, Revision: 2,
		UplinkBps: 200, DownlinkBps: 300,
	})
	if err != nil {
		t.Fatal(err)
	}
	req := feature.RateBarrierRequest{
		EntitlementID: uuid.New(), NodeID: uuid.New(),
		ResourceID: uuid.New(), OperationID: uuid.New(), Subscription: "a",
		Epoch: 1, Revision: 1, CoreRevision: 2, Up: 200, Down: 300,
	}
	bad := req
	bad.Up = 400
	if _, err := m.ProveRateBarrier(context.Background(), bad); err == nil {
		t.Fatal("core signed barrier for unapplied rate")
	}
	limit := m.ForEmail("member")
	stopped := make(chan struct{}, 1)
	untrack, err := limit.TrackConnection(func() { stopped <- struct{}{} })
	if err != nil {
		t.Fatal(err)
	}
	defer untrack()
	// Simulate a chunk admitted by the old limiter, still being forwarded.
	release, err := limit.Uplink.BeginRateTransfer(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	type result struct {
		sig []byte
		err error
	}
	completed := make(chan result, 1)
	go func() { sig, err := m.ProveRateBarrier(ctx, req); completed <- result{sig, err} }()
	select {
	case <-stopped:
		t.Fatal("ordinary rate reduction unexpectedly closed the VPN session")
	case res := <-completed:
		t.Fatalf("signed before old-rate payload finished: %v", res.err)
	case <-time.After(40 * time.Millisecond):
	}
	// Waiting for a payload transfer must not serialize unrelated policy and
	// lease operations; the manager lock is taken only for the final proof.
	policyRead := make(chan error, 1)
	go func() {
		_, err := m.GetSubscription("a")
		policyRead <- err
	}()
	select {
	case err := <-policyRead:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("rate barrier held global policy lock while waiting for payload")
	}
	release()
	select {
	case res := <-completed:
		if res.err != nil {
			t.Fatal(res.err)
		}
		msg := fmt.Appendf(nil, "elx-rate-barrier-v1\n%s\n%s\n%s\n%s\n%d\n%d\n%d\n%d",
			req.EntitlementID, req.NodeID, req.ResourceID, req.OperationID,
			req.Epoch, req.Revision, req.Up, req.Down)
		if !ed25519.Verify(pub, msg, res.sig) {
			t.Fatal("signed rate barrier transcript mismatches ledger")
		}
	case <-time.After(time.Second):
		t.Fatal("barrier did not complete after old payload exited")
	}
	select {
	case <-stopped:
		t.Fatal("barrier closed the still-active VPN session")
	default:
	}
	if next, err := limit.TrackConnection(func() {}); err != nil {
		t.Fatal("lower live rate policy remained blocked", err)
	} else {
		next()
	}
}
