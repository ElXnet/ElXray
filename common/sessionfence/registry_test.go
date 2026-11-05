package sessionfence

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestConcurrentAdmissionAndProfileDenial(t *testing.T) {
	r := New()
	id := [16]byte{1}
	other := [16]byte{2}
	if !r.Register(id) || !r.Register(other) {
		t.Fatal("register")
	}
	var stops atomic.Int64
	done := make(chan struct{})
	untrack, err := r.Track(id, func() { stops.Add(1); close(done) })
	if err != nil {
		t.Fatal(err)
	}
	otherUntrack, err := r.Track(other, func() { t.Error("other profile stopped") })
	if err != nil {
		t.Fatal(err)
	}
	callbacks, err := r.Deny(id)
	if err != nil || len(callbacks) != 1 {
		t.Fatal(err, len(callbacks))
	}
	if _, err := r.Track(id, func() {}); !errors.Is(err, ErrDenied) {
		t.Fatal("denied account admitted", err)
	}
	if _, err := r.Track(other, func() {}); err != nil {
		t.Fatal("independent VLESS account denied", err)
	}
	for _, stop := range callbacks {
		stop()
	}
	<-done
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); time.Sleep(20 * time.Millisecond); untrack(); otherUntrack() }()
	if err := r.Wait(ctx, id); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if stops.Load() != 1 {
		t.Fatal("connection was not stopped")
	}
}

func TestRestoreDenialAndIdempotentUntrack(t *testing.T) {
	r := New()
	id := [16]byte{5}
	r.Restore([][16]byte{id, id, {}})
	r.Register(id)
	if !r.IsDenied(id) {
		t.Fatal("registered profile was re-enabled")
	}
	if _, err := r.Track(id, func() {}); !errors.Is(err, ErrDenied) {
		t.Fatal(err)
	}
	if _, err := r.Deny([16]byte{6}); !errors.Is(err, ErrUnknown) {
		t.Fatal(err)
	}
	a := [16]byte{7}
	r.Register(a)
	untrack, err := r.Track(a, func() {})
	if err != nil {
		t.Fatal(err)
	}
	untrack()
	untrack()
	if n, err := r.Remaining(a); err != nil || n != 0 {
		t.Fatal(n, err)
	}
}
