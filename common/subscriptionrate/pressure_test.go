package subscriptionrate

import (
	"context"
	"errors"
	"testing"
	"time"
)

// These metrics describe limiter pressure, not the identity or rights of a
// device. They must be bound to a signed core incarnation before Control uses
// them for allocation decisions.
func TestPressureMeasuresBlockingWithoutCountingIdleCalls(t *testing.T) {
	limits := New(1, 1)
	limits.Uplink.RecordPayload(25)
	initial := limits.Uplink.Pressure()
	if initial.PayloadBytes != 25 || initial.BlockedCalls != 0 ||
		initial.ActiveWaiters != 0 || initial.BlockedNanos != 0 {
		t.Fatalf("incorrect initial counters: %+v", initial)
	}
	if err := limits.Downlink.WaitN(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if downstream := limits.Downlink.Pressure(); downstream.BlockedCalls != 0 || downstream.ActiveWaiters != 0 {
		t.Fatalf("unconstrained direction reported saturation: %+v", downstream)
	}
	if !limits.Uplink.AllowN(time.Now(), Burst) {
		t.Fatal("could not exhaust upload credit")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- limits.Uplink.WaitN(ctx, Burst) }()

	timeout := time.NewTimer(2 * time.Second)
	defer timeout.Stop()
	ready := false
	for !ready {
		sample := limits.Uplink.Pressure()
		if sample.BlockedCalls == 1 && sample.ActiveWaiters == 1 {
			ready = true
			break
		}
		select {
		case <-timeout.C:
			t.Fatalf("missing limiter pressure observation: %+v", sample)
		case <-time.After(time.Millisecond):
		}
	}
	time.Sleep(5 * time.Millisecond)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected cancellation result: %v", err)
	}
	completed := limits.Uplink.Pressure()
	if completed.BlockedCalls != 1 || completed.ActiveWaiters != 0 ||
		completed.BlockedNanos == 0 || completed.PayloadBytes != 25 {
		t.Fatalf("wait pressure not finalized: %+v", completed)
	}
	limits.Update(MaxRate, 1, false)
	if err := limits.Uplink.WaitN(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	after := limits.Uplink.Pressure()
	if after.BlockedCalls != completed.BlockedCalls || after.BlockedNanos != completed.BlockedNanos {
		t.Fatalf("policy change reset cumulative saturation: before=%+v after=%+v", completed, after)
	}
}

func TestPressureInvalidOrDisabledWaitDoesNotSignalDemand(t *testing.T) {
	limits := New(1, 1)
	if err := limits.Uplink.WaitN(context.Background(), Burst+1); err == nil {
		t.Fatal("invalid request accepted")
	}
	limits.Update(1, 1, true)
	if err := limits.Uplink.WaitN(context.Background(), Burst); !errors.Is(err, ErrDisabled) {
		t.Fatal(err)
	}
	pressure := limits.Uplink.Pressure()
	if pressure.BlockedCalls != 0 || pressure.ActiveWaiters != 0 {
		t.Fatalf("invalid/disabled request counted as pressure: %+v", pressure)
	}
}
