//go:build linux

package policy

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common/subscriptionrate"
	feature "github.com/xtls/xray-core/features/policy"
)

func barrierFixture(t *testing.T) (*Instance, ed25519.PublicKey) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.json")
	pub, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, []byte(`{"Version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path+".key", []byte(hex.EncodeToString(key.Seed())), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ELXRAY_POLICY_STATE", path)
	manager, err := New(context.Background(), &Config{
		RequireSubscription: true,
		Subscriptions: map[string]*SubscriptionPolicy{"a": {
			Emails: []string{"member"}, UplinkBps: 1000,
			DownlinkBps: 1000, Revision: 1,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	return manager, pub
}

func rateBarrierFixtureRequest() feature.RateBarrierRequest {
	return feature.RateBarrierRequest{
		EntitlementID: uuid.New(), NodeID: uuid.New(),
		ResourceID: uuid.New(), OperationID: uuid.New(), Subscription: "a",
		Epoch: 1, Revision: 1, CoreRevision: 2, Up: 200, Down: 300,
	}
}

func TestQuietBarrierRejectsNewerPolicyInsteadOfSigningOldRate(t *testing.T) {
	manager, _ := barrierFixture(t)
	_, err := manager.UpdateSubscription(subscriptionrate.Update{
		ID: "a", ExpectedRevision: 1, Revision: 2,
		UplinkBps: 200, DownlinkBps: 300,
	})
	if err != nil {
		t.Fatal(err)
	}
	release, err := manager.ForEmail("member").Uplink.BeginRateTransfer(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := manager.ProveRateBarrier(ctx, rateBarrierFixtureRequest())
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("barrier unexpectedly signed while payload was in flight: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	// Newer durable policy invalidates the older proof even if its speed
	// decreases again; the old operation must not free the wrong grant.
	_, err = manager.UpdateSubscription(subscriptionrate.Update{
		ID: "a", ExpectedRevision: 2, Revision: 3,
		UplinkBps: 150, DownlinkBps: 250,
	})
	if err != nil {
		t.Fatal(err)
	}
	release()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("signed an obsolete Control rate revision")
		}
	case <-ctx.Done():
		t.Fatal("obsolete rate barrier failed to terminate")
	}
	if stop, err := manager.ForEmail("member").TrackConnection(func() {}); err != nil {
		t.Fatalf("failed rate barrier disconnected VPN admission: %v", err)
	} else {
		stop()
	}
}

func TestFullDisabledRateBarrierStillRequiresFlowDrain(t *testing.T) {
	manager, pub := barrierFixture(t)
	limits := manager.ForEmail("member")
	stopped := make(chan struct{}, 1)
	untrack, err := limits.TrackConnection(func() { stopped <- struct{}{} })
	if err != nil {
		t.Fatal(err)
	}
	defer untrack()
	_, err = manager.UpdateSubscription(subscriptionrate.Update{
		ID: "a", ExpectedRevision: 1, Revision: 2,
		UplinkBps: 1, DownlinkBps: 1, Disabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-stopped:
	default:
		t.Fatal("disable did not request active VPN flow closure")
	}
	req := rateBarrierFixtureRequest()
	req.Up, req.Down = 0, 0
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	type result struct {
		proof []byte
		err   error
	}
	completed := make(chan result, 1)
	go func() {
		proof, err := manager.ProveRateBarrier(ctx, req)
		completed <- result{proof, err}
	}()
	select {
	case got := <-completed:
		t.Fatalf("signed disabled entitlement before old sockets closed: %+v", got)
	case <-time.After(25 * time.Millisecond):
	}
	untrack()
	select {
	case got := <-completed:
		if got.err != nil || len(got.proof) != ed25519.SignatureSize {
			t.Fatalf("disabled proof failed after flow drain: %+v", got)
		}
		if len(pub) != ed25519.PublicKeySize {
			t.Fatal("invalid fixture signing key")
		}
	case <-ctx.Done():
		t.Fatal("disabled rate barrier did not finish after drain")
	}
}
