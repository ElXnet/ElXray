// Package sessionfence tracks authenticated VLESS profile flows so a node
// can prove one particular profile was denied and drained. The registry never
// trusts IP addresses, headers, or user-supplied device identifiers.
package sessionfence

import (
	"context"
	"errors"
	"sync"
	"time"
)

var (
	ErrUnknown = errors.New("VLESS profile is not registered")
	ErrDenied  = errors.New("VLESS profile admission denied")
)

type profile struct {
	denied bool
	flows  map[*flow]struct{}
}
type flow struct{ stop func() }

// Registry serializes admission and deny, and does not count transient proxy
// connections until the VLESS account UUID has been authenticated.
type Registry struct {
	mu       sync.Mutex
	profiles map[[16]byte]*profile
}

func New() *Registry { return &Registry{profiles: make(map[[16]byte]*profile)} }

// Register is idempotent for users configured on multiple inbound handlers.
// Denial is NEVER cleared by registration or a dynamic AddUser.
func (r *Registry) Register(id [16]byte) bool {
	if id == [16]byte{} {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.profiles[id]; !exists {
		r.profiles[id] = &profile{flows: make(map[*flow]struct{})}
	}
	return true
}

func (r *Registry) Track(id [16]byte, stop func()) (func(), error) {
	if stop == nil {
		return nil, ErrUnknown
	}
	r.mu.Lock()
	p := r.profiles[id]
	if p == nil {
		r.mu.Unlock()
		return nil, ErrUnknown
	}
	if p.denied {
		r.mu.Unlock()
		return nil, ErrDenied
	}
	f := &flow{stop: stop}
	p.flows[f] = struct{}{}
	r.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			r.mu.Lock()
			delete(p.flows, f)
			r.mu.Unlock()
		})
	}, nil
}

// Deny atomically stops future admission and returns callbacks for active
// flows. The caller must durably persist this denial BEFORE running callbacks
// and especially before signing a drain receipt.
func (r *Registry) Deny(id [16]byte) ([]func(), error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p := r.profiles[id]
	if p == nil {
		return nil, ErrUnknown
	}
	p.denied = true
	stops := make([]func(), 0, len(p.flows))
	for f := range p.flows {
		stops = append(stops, f.stop)
	}
	return stops, nil
}

func (r *Registry) IsDenied(id [16]byte) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	p := r.profiles[id]
	return p != nil && p.denied
}

func (r *Registry) Remaining(id [16]byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p := r.profiles[id]
	if p == nil {
		return 0, ErrUnknown
	}
	return len(p.flows), nil
}

// Wait is not an admission gate: it only observes the already-denied profile.
// A bounded poll is intentional, avoiding a goroutine that outlives canceled
// RPCs or a timer leak during repeated failed drain attempts.
func (r *Registry) Wait(ctx context.Context, id [16]byte) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		r.mu.Lock()
		p := r.profiles[id]
		if p == nil || !p.denied {
			r.mu.Unlock()
			return ErrUnknown
		}
		n := len(p.flows)
		r.mu.Unlock()
		if n == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// Restore sets persisted denials before inbound profiles are registered.
// If a matching user appears later, it remains blocked.
func (r *Registry) Restore(ids [][16]byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, id := range ids {
		if id == [16]byte{} {
			continue
		}
		p := r.profiles[id]
		if p == nil {
			p = &profile{flows: make(map[*flow]struct{})}
			r.profiles[id] = p
		}
		p.denied = true
	}
}

// Denied returns a defensive copy of all blocked profile identifiers.
func (r *Registry) Denied() [][16]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	var ids [][16]byte
	for id, p := range r.profiles {
		if p.denied {
			ids = append(ids, id)
		}
	}
	return ids
}
