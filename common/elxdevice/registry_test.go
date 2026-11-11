package elxdevice

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

func mustKey(t *testing.T, profile, hwid string) Key {
	t.Helper()
	key, err := Parse(profile, hwid)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestRepeatedConnectionsCountOneDeviceNotOneSlotPerFlow(t *testing.T) {
	r := NewRegistry()
	a := mustKey(t, testProfile, "device-A")
	b := mustKey(t, testProfile, "device-B")
	doneA1, err := r.Observe(a, func() {})
	if err != nil {
		t.Fatal(err)
	}
	doneA2, err := r.Observe(a, func() {})
	if err != nil {
		t.Fatal(err)
	}
	doneB, err := r.Observe(b, func() {})
	if err != nil {
		t.Fatal(err)
	}
	if got := r.ActiveDevices(a.Profile); got != 2 {
		t.Fatalf("distinct devices = %d, expected 2", got)
	}
	if got := r.ActiveFlows(a); got != 2 {
		t.Fatalf("same device flows = %d, expected 2", got)
	}
	doneA1()
	doneA1()
	if got := r.ActiveDevices(a.Profile); got != 2 {
		t.Fatal("one closed tab removed still-active device", got)
	}
	doneA2()
	if got := r.ActiveDevices(a.Profile); got != 1 {
		t.Fatal("closed device still counted", got)
	}
	doneB()
	if got := r.ActiveDevices(a.Profile); got != 0 {
		t.Fatal("empty profile counted", got)
	}
}

func TestDenyStopsOnlyExactBindingAndNeverReenablesIt(t *testing.T) {
	r := NewRegistry()
	a := mustKey(t, testProfile, "device-A")
	b := mustKey(t, testProfile, "device-B")
	var stopped atomic.Int32
	releaseA, err := r.Observe(a, func() { stopped.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	releaseB, err := r.Observe(b, func() { t.Fatal("unrelated device flow closed") })
	if err != nil {
		t.Fatal(err)
	}
	callbacks, err := r.Deny(a)
	if err != nil || len(callbacks) != 1 {
		t.Fatal(err, len(callbacks))
	}
	// Callbacks can safely re-enter the registry without deadlocking.
	for _, stop := range callbacks {
		stop()
		releaseA()
	}
	if stopped.Load() != 1 {
		t.Fatal("exact device flow was not stopped")
	}
	if _, err := r.Observe(a, func() {}); !errors.Is(err, ErrRevoked) {
		t.Fatal("revoked device reconnected", err)
	}
	if _, err := r.Observe(b, func() {}); err != nil {
		t.Fatal("another device was revoked", err)
	}
	if callbacks, err := r.Deny(a); err != nil || len(callbacks) != 0 {
		t.Fatal("repeat deny emitted duplicate stops", err)
	}
	releaseB()
}

func TestRestoredDenialAndInvalidObservations(t *testing.T) {
	key := mustKey(t, testProfile, "device-A")
	r := &Registry{}
	if err := r.RestoreDenied([]Key{key, key}); err != nil {
		t.Fatal(err)
	}
	if !r.IsDenied(key) {
		t.Fatal("durably denied identity not restored")
	}
	if _, err := r.Observe(key, func() {}); !errors.Is(err, ErrRevoked) {
		t.Fatal(err)
	}
	if err := r.RestoreDenied([]Key{{}}); !errors.Is(err, ErrInvalidKey) {
		t.Fatal("zero denial accepted", err)
	}
	if _, err := r.Observe(Key{}, func() {}); !errors.Is(err, ErrInvalidKey) {
		t.Fatal(err)
	}
	another := mustKey(t, testProfile, "device-B")
	if _, err := r.Observe(another, nil); !errors.Is(err, ErrMissingStop) {
		t.Fatal(err)
	}
}

func TestConcurrentObserveAndDenyNeverReadmitsRevokedDevice(t *testing.T) {
	r := NewRegistry()
	key := mustKey(t, testProfile, "device-concurrent")
	const n = 120
	var wg sync.WaitGroup
	var releasesMu sync.Mutex
	var releases []func()
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, err := r.Observe(key, func() {})
			if err == nil {
				releasesMu.Lock()
				releases = append(releases, release)
				releasesMu.Unlock()
			} else if !errors.Is(err, ErrRevoked) {
				t.Errorf("unexpected observation error: %v", err)
			}
		}()
	}
	callbacks, err := r.Deny(key)
	if err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	for _, stop := range callbacks {
		stop()
	}
	releasesMu.Lock()
	for _, release := range releases {
		release()
	}
	releasesMu.Unlock()
	if !r.IsDenied(key) {
		t.Fatal("deny lost race against reconnect")
	}
	if _, err := r.Observe(key, func() {}); !errors.Is(err, ErrRevoked) {
		t.Fatal("reconnect accepted", err)
	}
	if got := r.ActiveDevices(key.Profile); got != 0 {
		t.Fatal("released flows remain active", got)
	}
}

func TestInactiveObservationsAreReclaimedButRevocationPersists(t *testing.T) {
	r := NewRegistry()
	for i := 0; i < 1000; i++ {
		key := mustKey(t, testProfile, fmt.Sprintf("ephemeral-%04d", i))
		done, err := r.Observe(key, func() {})
		if err != nil {
			t.Fatal(err)
		}
		done()
	}
	if got := len(r.records); got != 0 {
		t.Fatalf("released HWIDs retained in memory: %d", got)
	}
	key := mustKey(t, testProfile, "revoked-persistent")
	done, err := r.Observe(key, func() {})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Deny(key); err != nil {
		t.Fatal(err)
	}
	done()
	if !r.IsDenied(key) || len(r.records) != 1 {
		t.Fatal("a revoked pair was discarded after releasing its last flow")
	}
}
