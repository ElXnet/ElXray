// Package subscriptionrate provides per-subscription, per-core rate budgets.
package subscriptionrate

import (
	"context"
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// Burst is the maximum initial credit in bytes, independent of the configured rate.
const Burst = 8192

// MaxRate bounds configuration to a practical, exactly representable byte rate.
const MaxRate = uint64(1 << 40)

var ErrDisabled = errors.New("subscription is disabled")

// Limits is a stable, shared budget. Both directions exist even when unlimited,
// so existing connections can be limited later without allowing raw-copy bypass.
// Rates and disabled state change together under mu. Updates never replace buckets.
type Limits struct {
	mu          sync.Mutex
	changed     chan struct{}
	disabled    bool
	leaseRequired bool
	leaseDeadline time.Time
	leaseTripped bool
	connections map[*connectionStop]struct{}
	Uplink      *Budget
	Downlink    *Budget
}

// Budget is a byte token bucket. Waiters do not reserve future credit: a policy
// change can wake them immediately without inheriting old-rate reservations.
type Budget struct {
	owner   *Limits
	rate    uint64
	tokens  float64
	payload atomic.Uint64
	last    time.Time
}

func New(uplink, downlink uint64) *Limits {
	l := &Limits{changed: make(chan struct{})}
	now := time.Now()
	l.Uplink = &Budget{owner: l, rate: uplink, tokens: Burst, last: now}
	l.Downlink = &Budget{owner: l, rate: downlink, tokens: Burst, last: now}
	return l
}

func (b *Budget) refill(now time.Time) {
	if b.rate != 0 {
		b.tokens = math.Min(Burst, b.tokens+now.Sub(b.last).Seconds()*float64(b.rate))
	}
	b.last = now
}

type connectionStop struct {
	close func()
}

// TrackConnection registers a live connection for disable notification.
// close must only stop this connection and must not call the policy manager.
// The returned function removes the registration on normal connection exit.
func (l *Limits) TrackConnection(close func()) (func(), error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.disabled || l.leaseDue(time.Now()) {
		return nil, ErrDisabled
	}
	entry := &connectionStop{close: close}
	if l.connections == nil {
		l.connections = make(map[*connectionStop]struct{})
	}
	l.connections[entry] = struct{}{}
	return func() {
		l.mu.Lock()
		delete(l.connections, entry)
		l.mu.Unlock()
	}, nil
}

// RequireLease makes the budget fail closed until a verified Control
// heartbeat is installed. It does not change subscribed rates or issue a
// session-release receipt; occupied device slots remain accounted for.
func (l *Limits) RequireLease() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.leaseRequired = true
	l.leaseDeadline = time.Time{}
	l.leaseTripped = true
}

// RenewLease is called ONLY by the core's Ed25519-verifying policy manager.
// The deadline is a wall-clock upper bound: replaying a signed ticket cannot
// extend its original lifetime. It may only increase, never roll back.
func (l *Limits) RenewLease(deadline time.Time) {
	l.mu.Lock()
	now := time.Now()
	if !l.leaseRequired || !deadline.After(now) || !deadline.After(l.leaseDeadline) {
		l.mu.Unlock()
		return
	}
	// An expired lease requires a fresh VPN handshake. Even if the watchdog
	// has not yet fired, a late renewal must not resurrect old idle sockets.
	var stopped map[*connectionStop]struct{}
	if l.leaseDue(now) && !l.leaseTripped {
		stopped = l.connections
		l.connections = nil
	}
	l.leaseDeadline = deadline
	l.leaseTripped = false
	close(l.changed)
	l.changed = make(chan struct{})
	l.mu.Unlock()
	for f := range stopped {
		f.close()
	}
}

func (l *Limits) leaseDue(now time.Time) bool {
	return l.leaseRequired && (l.leaseTripped || !now.Before(l.leaseDeadline))
}

// SweepLease aborts ALL tracked sockets after expiry, including idle
// connections that would otherwise never reach WaitN. The caller repeats
// this for active subscriptions; closing callbacks run outside l.mu.
func (l *Limits) SweepLease(now time.Time) bool {
	l.mu.Lock()
	if !l.leaseDue(now) || l.leaseTripped {
		l.mu.Unlock()
		return false
	}
	l.leaseTripped = true
	stopped := l.connections
	l.connections = nil
	close(l.changed)
	l.changed = make(chan struct{})
	l.mu.Unlock()
	for f := range stopped {
		f.close()
	}
	return true
}

// Update atomically changes both rates and admission state, preserving credit.
// Callers validate rates against MaxRate before applying an external policy.
func (l *Limits) Update(uplink, downlink uint64, disabled bool) {
	l.mu.Lock()
	now := time.Now()
	l.Uplink.refill(now)
	l.Downlink.refill(now)
	l.Uplink.rate, l.Downlink.rate, l.disabled = uplink, downlink, disabled
	close(l.changed)
	l.changed = make(chan struct{})
	var stopped map[*connectionStop]struct{}
	if disabled {
		stopped = l.connections
		l.connections = nil
	}
	l.mu.Unlock()
	for entry := range stopped {
		entry.close()
	}
}

// AllowN is a non-blocking debit, also useful to exhaust initial test credit.
func (b *Budget) AllowN(now time.Time, n int) bool {
	l := b.owner
	l.mu.Lock()
	defer l.mu.Unlock()
	b.refill(now)
	if n < 0 || n > Burst || l.disabled || l.leaseDue(now) {
		return false
	}
	if b.rate != 0 && b.tokens < float64(n) {
		return false
	}
	// Unlimited traffic cannot manufacture fresh credit on a later transition.
	b.tokens = math.Max(0, b.tokens-float64(n))
	return true
}

func (b *Budget) WaitN(ctx context.Context, n int) error {
	if n < 0 || n > Burst {
		return errors.New("rate wait exceeds burst")
	}
	l := b.owner
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		l.mu.Lock()
		now := time.Now()
		b.refill(now)
		if l.disabled || l.leaseDue(now) {
			l.mu.Unlock()
			return ErrDisabled
		}
		if b.rate == 0 || b.tokens >= float64(n) {
			b.tokens = math.Max(0, b.tokens-float64(n))
			l.mu.Unlock()
			return nil
		}
		delay := time.Duration(math.Ceil((float64(n) - b.tokens) / float64(b.rate) * float64(time.Second)))
		changed := l.changed
		l.mu.Unlock()
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-changed:
			timer.Stop()
		case <-timer.C:
		}
	}
}

// RecordPayload counts bytes accepted at the dispatcher boundary. It does
// not count limiter reservations or wire overhead.
func (b *Budget) RecordPayload(n int32) {
	if n > 0 {
		b.payload.Add(uint64(n))
	}
}

func (b *Budget) PayloadBytes() uint64 { return b.payload.Load() }
