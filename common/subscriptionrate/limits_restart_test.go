package subscriptionrate

import (
	"testing"
	"time"
)

func TestManagedLeaseRebootAndRecoveryDiscardStoredBurst(t *testing.T) {
	l := New(10, 20)
	if !l.Uplink.AllowN(time.Now(), 1024) {
		t.Fatal("expected initial standalone test credit")
	}
	l.RequireLease()
	l.mu.Lock()
	if l.Uplink.tokens != 0 || l.Downlink.tokens != 0 {
		t.Fatal("managed restart kept pre-lease token burst")
	}
	l.mu.Unlock()
	if !l.RenewLease(time.Now().Add(15 * time.Second)) {
		t.Fatal("signed lease activation was rejected by the limiter")
	}
	l.mu.Lock()
	if l.Uplink.tokens != 0 || l.Downlink.tokens != 0 {
		t.Fatal("new lease reintroduced accumulated dormant token credit")
	}
	l.mu.Unlock()
	l.RequireLease()
	if !l.RenewLease(time.Now().Add(16 * time.Second)) {
		t.Fatal("fresh signed deadline could not recover the lease")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.Uplink.tokens != 0 || l.Downlink.tokens != 0 {
		t.Fatal("recovered managed flow received extra initial burst")
	}
}
