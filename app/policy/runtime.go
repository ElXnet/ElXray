package policy

import (
	"errors"
	"maps"
	"math"
	"slices"
	"strings"

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
		p.UplinkBps, p.DownlinkBps, p.Disabled, p.Revision = u.UplinkBps, u.DownlinkBps, u.Disabled, u.Revision
		if m.store != nil {
			next := maps.Clone(m.subscriptionPolicies)
			next[u.ID] = p
			if err := m.store.write(next); err != nil {
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
