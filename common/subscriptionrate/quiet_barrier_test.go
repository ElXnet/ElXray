package subscriptionrate

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func awaitQuiet(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("quiet barrier did not reach expected state")
}

// A rate reduction is allowed to pause new payload chunks, but must not
// request that VLESS/TCP/Mux sessions close just to redistribute bandwidth.
func TestQuietRateBarrierPreservesLiveConnectionsAndWaitsForChunks(t *testing.T) {
	l := New(200, 300)
	var stops atomic.Int32
	untrack, err := l.TrackConnection(func() { stops.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	defer untrack()
	release, err := l.Uplink.BeginRateTransfer(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	proved := make(chan struct{})
	done := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	go func() {
		_, err := l.WithQuietRateBarrier(ctx, func() ([]byte, error) {
			close(proved)
			return []byte("signed"), nil
		})
		done <- err
	}()
	awaitQuiet(t, func() bool {
		l.mu.Lock()
		defer l.mu.Unlock()
		return l.rateQuiescing
	})
	// Old credited payload must complete, and new payload must wait rather
	// than fail with ErrDisabled while the rate proof is being prepared.
	nextDone := make(chan error, 1)
	go func() {
		releaseNext, err := l.Downlink.BeginRateTransfer(ctx)
		if err == nil {
			releaseNext()
		}
		nextDone <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("signed while pre-reduction chunk still in flight: %v", err)
	case <-proved:
		t.Fatal("signed before old-rate payload finished")
	case err := <-nextDone:
		t.Fatalf("new chunk passed quiesce gate: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	l.Update(100, 150, false) // in-place reduction affects both budgets
	release()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("quiet barrier did not complete after old chunk exited")
	}
	select {
	case err := <-nextDone:
		if err != nil {
			t.Fatalf("new chunk was disconnected by barrier: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("new rate transfer remained stuck after barrier")
	}
	if stops.Load() != 0 {
		t.Fatal("non-disruptive rate barrier closed a tracked VPN connection")
	}
}

func TestQuietRateBarrierTimeoutDoesNotSignOrLeakGate(t *testing.T) {
	l := New(100, 100)
	release, err := l.Uplink.BeginRateTransfer(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	signed := false
	if _, err := l.WithQuietRateBarrier(ctx, func() ([]byte, error) {
		signed = true
		return []byte("invalid"), nil
	}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("failed to time out blocked quiet barrier: %v", err)
	}
	if signed {
		t.Fatal("barrier signed without finishing old payload")
	}
	nextCtx, done := context.WithTimeout(context.Background(), time.Second)
	defer done()
	next, err := l.Downlink.BeginRateTransfer(nextCtx)
	if err != nil {
		t.Fatalf("timed out rate barrier did not release gate: %v", err)
	}
	next()
}

func TestQuietRateBarrierSerializesConcurrentProofsAndDrains(t *testing.T) {
	l := New(100, 100)
	release, err := l.Uplink.BeginRateTransfer(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := l.WithQuietRateBarrier(ctx, func() ([]byte, error) {
			return []byte("signed"), nil
		})
		done <- err
	}()
	awaitQuiet(t, func() bool {
		l.mu.Lock()
		defer l.mu.Unlock()
		return l.rateQuiescing
	})
	if _, err := l.WithQuietRateBarrier(ctx, func() ([]byte, error) { return nil, nil }); err == nil {
		t.Fatal("accepted concurrent quiet proof")
	}
	if err := l.DrainForRateBarrier(ctx); err == nil {
		t.Fatal("allowed disruptive drain to race a quiet rate proof")
	}
	release()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
