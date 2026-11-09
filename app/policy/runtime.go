package policy

import (
	"errors"
	"maps"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/xtls/xray-core/common/subscriptionrate"
)

func (m *Instance) GetSubscription(id string) (subscriptionrate.Policy, error) {
	m.subscriptionMu.Lock()
	defer m.subscriptionMu.Unlock()
	p, ok := m.subscriptionPolicies[id]
	if !ok {
		return subscriptionrate.Policy{}, subscriptionrate.ErrNotFound
	}
	p.Emails = slices.Clone(p.Emails)
	return p, nil
}

func (m *Instance) UpdateSubscription(u subscriptionrate.Update) (subscriptionrate.Policy, error) {
	if u.ID == "" || len(u.ID) > 1024 || u.ExpectedRevision == 0 || u.ExpectedRevision == math.MaxUint64 || u.Revision != u.ExpectedRevision+1 || u.UplinkBps > subscriptionrate.MaxRate || u.DownlinkBps > subscriptionrate.MaxRate {
		return subscriptionrate.Policy{}, subscriptionrate.ErrInvalid
	}
	m.subscriptionMu.Lock()
	defer m.subscriptionMu.Unlock()
	p, ok := m.subscriptionPolicies[u.ID]
	if !ok {
		return subscriptionrate.Policy{}, subscriptionrate.ErrNotFound
	}
	if m.store != nil && m.store.failed {
		return subscriptionrate.Policy{}, errors.New("policy store unavailable")
	}
	same := p.UplinkBps == u.UplinkBps && p.DownlinkBps == u.DownlinkBps && p.Disabled == u.Disabled
	// An acknowledged update can be retried after a lost response, without credit reset.
	if !(u.Revision == p.Revision && same) {
		if u.ExpectedRevision != p.Revision {
			return subscriptionrate.Policy{}, subscriptionrate.ErrConflict
		}
		limits := m.subscriptions[strings.ToLower(p.Emails[0])]
		// In lease-enforced mode, a caller can never turn a reduction, an
		// outdated reservation or a disabled subscription into a new grant.
		// Verify the actual accepted, still-enforced, node-bound Control
		// ceiling ON EVERY enabling/increasing update, not only at Renew.
		// Deny and monotonic reductions remain available during an outage.
		if len(m.leasePublicKey) != 0 {
			if u.UplinkBps == 0 || u.DownlinkBps == 0 || limits == nil {
				return subscriptionrate.Policy{}, subscriptionrate.ErrUnauthorized
			}
			requiresGrant := !u.Disabled && (p.Disabled || u.UplinkBps > p.UplinkBps || u.DownlinkBps > p.DownlinkBps)
			if u.Disabled && (u.UplinkBps > p.UplinkBps || u.DownlinkBps > p.DownlinkBps) {
				return subscriptionrate.Policy{}, subscriptionrate.ErrUnauthorized
			}
			if requiresGrant {
				t, ok := m.leaseAccepted[u.ID]
				deadline, active := limits.ActiveLeaseDeadline()
				if !ok || !active || !deadline.After(time.Now().Add(time.Second)) ||
					t.NodeID != m.leaseNodeID || t.Subscription != u.ID || t.Sequence <= 0 ||
					m.leaseSeq[u.ID] != t.Sequence || t.NotAfter <= time.Now().Unix()+1 ||
					t.CeilingUp <= 0 || t.CeilingDown <= 0 ||
					u.UplinkBps > uint64(t.CeilingUp) || u.DownlinkBps > uint64(t.CeilingDown) {
					return subscriptionrate.Policy{}, subscriptionrate.ErrUnauthorized
				}
			}
		}
		p.UplinkBps, p.DownlinkBps, p.Disabled, p.Revision = u.UplinkBps, u.DownlinkBps, u.Disabled, u.Revision
		if m.store != nil {
			next := maps.Clone(m.subscriptionPolicies)
			next[u.ID] = p
			if err := m.store.write(next, m.profileGate.Denied()); err != nil {
				m.store.failed = true
				return subscriptionrate.Policy{}, err
			}
		}
		limits.Update(u.UplinkBps, u.DownlinkBps, u.Disabled)
		m.subscriptionPolicies[u.ID] = p
	}
	p.Emails = slices.Clone(p.Emails)
	return p, nil
}
