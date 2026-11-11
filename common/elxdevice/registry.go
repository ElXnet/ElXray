package elxdevice

import (
	"errors"
	"sync"
)

var (
	ErrInvalidKey  = errors.New("invalid observed device key")
	ErrMissingStop = errors.New("device observation requires a flow stop callback")
	ErrRevoked     = errors.New("observed device was revoked")
)

type flow struct{ stop func() }
type observed struct {
	revoked bool
	flows   map[*flow]struct{}
}

// Registry tracks active connections already authenticated and admitted by
// the caller. Observe is NOT an admission operation and MUST only be invoked
// after Control-authorized profile/device policy is enforced at the data path.
// No slot limit, payment or ownership decision is made here.
type Registry struct {
	mu      sync.Mutex
	records map[Key]*observed
}

func NewRegistry() *Registry { return &Registry{records: make(map[Key]*observed)} }

// Observe registers an admitted connection and returns an idempotent release
// callback. A revoked device cannot be reintroduced by reconnecting.
func (r *Registry) Observe(key Key, stop func()) (func(), error) {
	if r == nil || !key.Valid() {
		return nil, ErrInvalidKey
	}
	if stop == nil {
		return nil, ErrMissingStop
	}
	r.mu.Lock()
	if r.records == nil {
		r.records = make(map[Key]*observed)
	}
	p := r.records[key]
	if p == nil {
		p = &observed{flows: make(map[*flow]struct{})}
		r.records[key] = p
	}
	if p.revoked {
		r.mu.Unlock()
		return nil, ErrRevoked
	}
	f := &flow{stop: stop}
	p.flows[f] = struct{}{}
	r.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			r.mu.Lock()
			delete(p.flows, f)
			// Discard inactive, non-revoked observations. Otherwise a long-lived
			// core would retain one map entry for every HWID ever seen. Denied
			// entries are intentionally retained until durable policy recovery.
			if len(p.flows) == 0 && !p.revoked && r.records[key] == p {
				delete(r.records, key)
			}
			r.mu.Unlock()
		})
	}, nil
}

// Deny marks one exact UUID+HWID identity as denied. It returns callbacks
// without executing them while holding the lock. The calling policy layer
// must persist any required revocation BEFORE running the returned stops.
// A repeat Deny is idempotent and never yields duplicate callbacks.
func (r *Registry) Deny(key Key) ([]func(), error) {
	if r == nil || !key.Valid() {
		return nil, ErrInvalidKey
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.records == nil {
		r.records = make(map[Key]*observed)
	}
	p := r.records[key]
	if p == nil {
		p = &observed{flows: make(map[*flow]struct{})}
		r.records[key] = p
	}
	if p.revoked {
		return nil, nil
	}
	p.revoked = true
	stops := make([]func(), 0, len(p.flows))
	for f := range p.flows {
		stops = append(stops, f.stop)
	}
	return stops, nil
}

// RestoreDenied reinstates previously persisted denials before connections
// can be observed. This registry is memory-only; durability is external.
func (r *Registry) RestoreDenied(keys []Key) error {
	if r == nil {
		return ErrInvalidKey
	}
	for _, key := range keys {
		if !key.Valid() {
			return ErrInvalidKey
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.records == nil {
		r.records = make(map[Key]*observed)
	}
	for _, key := range keys {
		p := r.records[key]
		if p == nil {
			p = &observed{flows: make(map[*flow]struct{})}
			r.records[key] = p
		}
		p.revoked = true
	}
	return nil
}

// ActiveFlows counts currently tracked flows for the exact binding.
func (r *Registry) ActiveFlows(key Key) int {
	if r == nil || !key.Valid() {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if p := r.records[key]; p != nil {
		return len(p.flows)
	}
	return 0
}

// ActiveDevices counts DISTINCT HWIDs currently having active connections
// under the exact profile. It is telemetry, not the authoritative slot count.
func (r *Registry) ActiveDevices(profile [16]byte) int {
	if r == nil || profile == [16]byte{} {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	count := 0
	for key, entry := range r.records {
		if key.Profile == profile && len(entry.flows) > 0 {
			count++
		}
	}
	return count
}

func (r *Registry) IsDenied(key Key) bool {
	if r == nil || !key.Valid() {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	entry := r.records[key]
	return entry != nil && entry.revoked
}
