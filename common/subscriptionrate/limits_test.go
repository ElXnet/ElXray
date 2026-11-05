package subscriptionrate

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestUpdatesPreserveCreditAndWakeWaiters(t *testing.T) {
	for _, mode := range []string{"unlimited", "faster", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			l := New(1, 0)
			if !l.Uplink.AllowN(time.Now(), Burst) {
				t.Fatal("initial credit missing")
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- l.Uplink.WaitN(ctx, Burst) }()
			// Establish a blocked wait at the old rate (8192 seconds).
			time.Sleep(20 * time.Millisecond)
			switch mode {
			case "unlimited":
				l.Update(0, 0, false)
			case "faster":
				l.Update(MaxRate, 0, false)
			case "disabled":
				l.Update(1, 0, true)
			}
			select {
			case err := <-done:
				if mode == "disabled" {
					if !errors.Is(err, ErrDisabled) {
						t.Fatal(err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal("old-rate wait survived an update")
			}
		})
	}
	l := New(1, 0)
	l.Uplink.AllowN(time.Now(), Burst)
	for range 100 {
		l.Update(1, 0, false)
	}
	if l.Uplink.AllowN(time.Now(), 1) {
		t.Fatal("update reissued initial credit")
	}
	// Neither direction is replaced, including unlimited -> limited.
	up, down := l.Uplink, l.Downlink
	down.AllowN(time.Now(), Burst)
	l.Update(0, 0, false)
	l.Update(1, 1, false)
	if l.Uplink != up || l.Downlink != down || down.AllowN(time.Now(), 1) {
		t.Fatal("transition reset budget")
	}
}

func TestBudgetAggregateIndependentDirectionsAndCancellation(t *testing.T) {
	l := New(128*1024, 128*1024)
	l.Uplink.AllowN(time.Now(), Burst)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			if err := l.Uplink.WaitN(ctx, Burst); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if time.Since(start) < 200*time.Millisecond {
		t.Fatal("parallel waits multiplied budget")
	}
	if !l.Downlink.AllowN(time.Now(), Burst) {
		t.Fatal("upload consumed download credit")
	}
	slow := New(1, 0)
	slow.Uplink.AllowN(time.Now(), Burst)
	expired, stop := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer stop()
	if err := slow.Uplink.WaitN(expired, Burst); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if err := slow.Uplink.WaitN(ctx, Burst+1); err == nil {
		t.Fatal("oversized wait accepted")
	}
}

func TestDisableStopsOnlyRegisteredConnections(t *testing.T) {
	limits := New(10, 10)
	var stopped, removed, next int
	detach, err := limits.TrackConnection(func() { removed++ })
	if err != nil {
		t.Fatal(err)
	}
	detach()
	_, err = limits.TrackConnection(func() { stopped++ })
	if err != nil {
		t.Fatal(err)
	}
	limits.Update(8, 8, false)
	if stopped != 0 {
		t.Fatal("rate update closed an active connection")
	}
	limits.Update(8, 8, true)
	if stopped != 1 || removed != 0 {
		t.Fatalf("unexpected stops: active=%d detached=%d", stopped, removed)
	}
	if _, err := limits.TrackConnection(func() {}); !errors.Is(err, ErrDisabled) {
		t.Fatalf("disabled subscription admitted connection: %v", err)
	}
	limits.Update(8, 8, false)
	_, err = limits.TrackConnection(func() { next++ })
	if err != nil {
		t.Fatal(err)
	}
	limits.Update(8, 8, true)
	if stopped != 1 || next != 1 {
		t.Fatalf("unexpected stops after re-enable: old=%d new=%d", stopped, next)
	}
}
