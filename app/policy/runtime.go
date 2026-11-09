package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/xtls/xray-core/common/subscriptionrate"
	"github.com/xtls/xray-core/common/elxjournal"
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

// ManagedUpdateHash covers the exact v1 runtime mutation body and its CAS
// revision; Control and ElXray must agree on these bytes before any intent
// is written. This is an integrity digest, NOT an authority signature.
func ManagedUpdateHash(u subscriptionrate.Update) string {
	t := fmt.Appendf(nil, "elx-managed-update-v1\n%s\n%d\n%d\n%d\n%d\n%t",
		u.ID, u.ExpectedRevision, u.Revision, u.UplinkBps, u.DownlinkBps, u.Disabled)
	sum := sha256.Sum256(t)
	return hex.EncodeToString(sum[:])
}

func (m *Instance) UpdateSubscription(u subscriptionrate.Update) (subscriptionrate.Policy, error) {
	return m.updateSubscription(u, nil)
}

// UpdateManagedSubscription is reachable only through the OS-authenticated
// Commander path. Its identity fields come from Control's signed authority
// binding and the trusted node agent, not from a VPN client connection.
func (m *Instance) UpdateManagedSubscription(u subscriptionrate.Update, cmd elxjournal.Command) (subscriptionrate.Policy, error) {
	return m.updateSubscription(u, &cmd)
}

func (m *Instance) updateSubscription(u subscriptionrate.Update, cmd *elxjournal.Command) (subscriptionrate.Policy, error) {
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
	if m.opJournal != nil {
		if cmd == nil {
			return subscriptionrate.Policy{}, subscriptionrate.ErrUnauthorized
		}
		binding, bound := m.leaseBindings[u.ID]
		if !bound || cmd.Kind != "set-rate" || cmd.NodeID != m.leaseNodeID.String() ||
			cmd.ResourceID != binding.ResourceID.String() || cmd.ExecutorID != binding.ExecutorID.String() ||
			cmd.AuthorityGeneration < binding.MinAuthorityGeneration ||
			cmd.ExpectedRevision != u.ExpectedRevision || cmd.NewRevision != u.Revision ||
			cmd.PayloadSHA256 != ManagedUpdateHash(u) {
			return subscriptionrate.Policy{}, subscriptionrate.ErrUnauthorized
		}
		if prior, exists := m.opJournal.Get(cmd.OperationID); exists {
			if prior.Command != *cmd {
				return subscriptionrate.Policy{}, elxjournal.ErrCollision
			}
			if prior.State != "APPLIED" || p.Revision != u.Revision ||
				p.UplinkBps != u.UplinkBps || p.DownlinkBps != u.DownlinkBps || p.Disabled != u.Disabled {
				return subscriptionrate.Policy{}, elxjournal.ErrUncertain
			}
			p.Emails = slices.Clone(p.Emails)
			return p, nil
		}
	} else if cmd != nil {
		return subscriptionrate.Policy{}, subscriptionrate.ErrUnauthorized
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
				binding, bound := m.leaseBindings[u.ID]
				t, ok := m.leaseAccepted[u.ID]
				deadline, active := limits.VerifiedLeaseDeadline()
				if !ok || !active || !deadline.After(time.Now().Add(time.Second)) ||
					!bound || t.Version != 3 || t.NodeID != m.leaseNodeID ||
					t.ResourceID != binding.ResourceID || t.ExecutorID != binding.ExecutorID ||
					t.AuthorityGeneration < binding.MinAuthorityGeneration ||
					t.AuthorityGeneration != m.leaseGeneration[u.ID] ||
					t.Subscription != u.ID || t.Sequence <= 0 ||
					m.leaseSeq[u.ID] != t.Sequence || t.NotAfter <= time.Now().Unix()+1 ||
					t.CeilingUp <= 0 || t.CeilingDown <= 0 ||
					u.UplinkBps > uint64(t.CeilingUp) || u.DownlinkBps > uint64(t.CeilingDown) {
					return subscriptionrate.Policy{}, subscriptionrate.ErrUnauthorized
				}
			}
		}
		if cmd != nil {
			record, err := m.opJournal.Begin(*cmd)
			if err != nil {
				return subscriptionrate.Policy{}, err
			}
			if record.State != "INTENT" {
				return subscriptionrate.Policy{}, elxjournal.ErrUncertain
			}
		}
		p.UplinkBps, p.DownlinkBps, p.Disabled, p.Revision = u.UplinkBps, u.DownlinkBps, u.Disabled, u.Revision
		if m.store != nil {
			next := maps.Clone(m.subscriptionPolicies)
			next[u.ID] = p
			if err := m.store.write(next, m.profileGate.Denied()); err != nil {
				m.store.failed = true
				if cmd != nil {
					limits.RequireLease()
					limits.Update(p.UplinkBps, p.DownlinkBps, true)
				}
				return subscriptionrate.Policy{}, err
			}
		}
		limits.Update(u.UplinkBps, u.DownlinkBps, u.Disabled)
		m.subscriptionPolicies[u.ID] = p
		if cmd != nil {
			// This receipt is created only AFTER policy write/fsync and
			// live limiter readback, never on submission or intent alone.
			if got := m.subscriptionPolicies[u.ID]; got.Revision != u.Revision ||
				got.UplinkBps != u.UplinkBps || got.DownlinkBps != u.DownlinkBps || got.Disabled != u.Disabled {
				m.store.failed = true
				limits.RequireLease()
				limits.Update(u.UplinkBps, u.DownlinkBps, true)
				return subscriptionrate.Policy{}, elxjournal.ErrUncertain
			}
			if _, err := m.opJournal.MarkApplied(cmd.OperationID); err != nil {
				m.store.failed = true
				limits.RequireLease()
				limits.Update(u.UplinkBps, u.DownlinkBps, true)
				return subscriptionrate.Policy{}, fmt.Errorf("managed operation outcome unknown: %w", err)
			}
		}
	}
	p.Emails = slices.Clone(p.Emails)
	return p, nil
}
