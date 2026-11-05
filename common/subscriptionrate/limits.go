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
	mu            sync.Mutex
	changed       chan struct{}
	disabled      bool
	leaseRequired bool
	leaseDeadline time.Time
	leaseTripped  bool
	barrierActive bool
	// rateQuiescing pauses new rate-guarded payload transfers without
	// disconnecting a VPN session. Existing transfers finish before the
	// signed lower-rate commitment can be released by Control.
	rateQuiescing bool
	inflightRate  int
	connections   map[*connectionStop]struct{}
	Uplink        *Budget
	Downlink      *Budget
}

// Budget is a byte token bucket. Waiters do not reserve future credit: a policy
// change can wake them immediately without inheriting old-rate reservations.
type Budget struct {
	owner         *Limits
	rate          uint64
	tokens        float64
	payload       atomic.Uint64
	blockedCalls  atomic.Uint64
	blockedNanos  atomic.Uint64
	activeWaiters atomic.Int64
	last          time.Time
}

// PressureSnapshot is local, cumulative limiter telemetry for one direction.
// PayloadBytes counts dispatcher payload, BlockedCalls counts WaitN calls
// forced to wait for tokens, BlockedNanos sums elapsed blocked time (including
// canceled calls), and ActiveWaiters is the live number of such calls.
// It is not cryptographically authenticated and is NOT a permission to raise
// the grant. Control must only trust signed, core-identity-bound observations.
type PressureSnapshot struct {
	PayloadBytes  uint64
	BlockedCalls  uint64
	BlockedNanos  uint64
	ActiveWaiters int64
}

// Pressure reports independent, monotonic counters and a live waiter gauge.
// Fields use atomic loads but are not one transactional snapshot. For demand
// estimation, compare consecutive samples from the SAME core incarnation.
func (b *Budget) Pressure() PressureSnapshot {
	return PressureSnapshot{
		PayloadBytes:  b.payload.Load(),
		BlockedCalls:  b.blockedCalls.Load(),
		BlockedNanos:  b.blockedNanos.Load(),
		ActiveWaiters: b.activeWaiters.Load(),
	}
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
	close   func()
	stopped bool
}

// stopConnectionsLocked never removes active flow registrations. Only the
// inbound's deferred untrack proves that the flow actually exited. Otherwise
// a rate barrier could sign early while TCP/Mux streams are still closing.
func (l *Limits) stopConnectionsLocked() []func() {
	stops := make([]func(), 0, len(l.connections))
	for entry := range l.connections {
		if !entry.stopped {
			entry.stopped = true
			stops = append(stops, entry.close)
		}
	}
	return stops
}

// TrackConnection registers a live connection for disable notification.
// close must only stop this connection and must not call the policy manager.
// The returned function removes the registration on normal connection exit.
func (l *Limits) TrackConnection(close func()) (func(), error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.disabled || l.barrierActive || l.leaseDue(time.Now()) {
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
	var stopped []func()
	if l.leaseDue(now) && !l.leaseTripped {
		stopped = l.stopConnectionsLocked()
	}
	l.leaseDeadline = deadline
	l.leaseTripped = false
	close(l.changed)
	l.changed = make(chan struct{})
	l.mu.Unlock()
	for _, stop := range stopped {
		stop()
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
	stopped := l.stopConnectionsLocked()
	close(l.changed)
	l.changed = make(chan struct{})
	l.mu.Unlock()
	for _, stop := range stopped {
		stop()
	}
	return true
}

// DrainForRateBarrier temporarily denies new subscription flows, cancels
// every previously admitted connection, and waits until all have exited.
// The signed barrier MUST NOT be produced before this returns nil. In
// particular an ordinary policy ACK cannot substitute for this drain.
func (l *Limits) DrainForRateBarrier(ctx context.Context) error {
	l.mu.Lock()
	if l.barrierActive || l.rateQuiescing {
		l.mu.Unlock()
		return errors.New("subscription rate barrier already in progress")
	}
	l.barrierActive = true
	close(l.changed)
	l.changed = make(chan struct{})
	stops := l.stopConnectionsLocked()
	l.mu.Unlock()
	for _, stop := range stops {
		stop()
	}
	defer func() {
		l.mu.Lock()
		l.barrierActive = false
		close(l.changed)
		l.changed = make(chan struct{})
		l.mu.Unlock()
	}()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		l.mu.Lock()
		remaining := len(l.connections)
		l.mu.Unlock()
		if remaining == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// BeginRateTransfer protects one payload chunk, including token acquisition
// and delivery to the next dispatcher writer. A signed non-disruptive barrier
// must wait for every earlier chunk to leave this region before it signs.
// This guard belongs to the existing shared subscription budget, not a
// connection-specific limiter, so all of its TCP/UDP/Mux flows participate.
//
// New transfers wait briefly during a quiet rate barrier. They do NOT receive
// ErrDisabled and existing sockets remain registered. The returned release
// function must be called once on every path (including write failure and
// canceled token waits). It is safe to call more than once.
func (b *Budget) BeginRateTransfer(ctx context.Context) (func(), error) {
	l := b.owner
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		l.mu.Lock()
		if l.disabled || l.barrierActive || l.leaseDue(time.Now()) {
			l.mu.Unlock()
			return nil, ErrDisabled
		}
		if l.rateQuiescing {
			changed := l.changed
			l.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-changed:
				continue
			}
		}
		l.inflightRate++
		l.mu.Unlock()
		var once sync.Once
		return func() {
			once.Do(func() {
				l.mu.Lock()
				l.inflightRate--
				if l.inflightRate == 0 && l.rateQuiescing {
					close(l.changed)
					l.changed = make(chan struct{})
				}
				l.mu.Unlock()
			})
		}, nil
	}
}

// WithQuietRateBarrier proves that no payload chunk admitted under the old
// rate remains in the instrumented dispatcher path. Unlike a profile drain,
// it preserves tracked VPN connections and the lower in-place token buckets.
// The caller must have already persisted the reduced policy and MUST recheck
// its exact core revision while signing. If an unbounded downstream write
// blocks, the context expires, no proof is emitted and Control must keep the
// old rate commitment reserved.
func (l *Limits) WithQuietRateBarrier(ctx context.Context, prove func() ([]byte, error)) ([]byte, error) {
	if prove == nil {
		return nil, errors.New("rate barrier proof function is required")
	}
	l.mu.Lock()
	if l.rateQuiescing || l.barrierActive {
		l.mu.Unlock()
		return nil, errors.New("subscription rate barrier already in progress")
	}
	l.rateQuiescing = true
	close(l.changed)
	l.changed = make(chan struct{})
	l.mu.Unlock()
	defer func() {
		l.mu.Lock()
		l.rateQuiescing = false
		close(l.changed)
		l.changed = make(chan struct{})
		l.mu.Unlock()
	}()
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		l.mu.Lock()
		if l.inflightRate == 0 {
			l.mu.Unlock()
			break
		}
		changed := l.changed
		l.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-changed:
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Keep new dispatcher transfers paused across the exact-revision
	// readback and signature. Do not hold l.mu while prove takes the policy
	// manager lock; UpdateSubscription acquires them in the opposite order.
	return prove()
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
	var stopped []func()
	if disabled {
		stopped = l.stopConnectionsLocked()
	}
	l.mu.Unlock()
	for _, stop := range stopped {
		stop()
	}
}

// AllowN is a non-blocking debit, also useful to exhaust initial test credit.
func (b *Budget) AllowN(now time.Time, n int) bool {
	l := b.owner
	l.mu.Lock()
	defer l.mu.Unlock()
	b.refill(now)
	if n < 0 || n > Burst || l.disabled || l.barrierActive || l.leaseDue(now) {
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
	waited := false
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		l.mu.Lock()
		now := time.Now()
		b.refill(now)
		if l.disabled || l.barrierActive || l.leaseDue(now) {
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
		// Track only a genuinely token-limited wait; a normal permitted
		// payload debit and an unrelated lease/disable error are not demand.
		// A policy update may wake this waiter many times, but it is counted
		// once until this WaitN call returns.
		if !waited {
			waited = true
			started := time.Now()
			b.blockedCalls.Add(1)
			b.activeWaiters.Add(1)
			defer func() {
				b.activeWaiters.Add(-1)
				b.blockedNanos.Add(uint64(time.Since(started)))
			}()
		}
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
