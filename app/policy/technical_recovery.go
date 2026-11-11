package policy

import (
	"github.com/google/uuid"
	"github.com/xtls/xray-core/common/elxjournal"
)

// RecoveredTechnicalProfiles is called during construction of a tagged VLESS
// inbound, before listeners accept traffic. A technical INSTALL is durable
// but its user is only in the in-memory VLESS validator. On restart, rebuild
// the exact identity from the fsynced journal; never fall back to a static
// operator JSON profile or assume the previous core incarnation is live.
//
// This is deliberately non-admitting. The technical VLESS payload gate stays
// disabled until the later independently proven owner/device protocol exists.
func (m *Instance) RecoveredTechnicalProfiles(inboundTag string) ([]elxjournal.TechnicalProfile, error) {
	if m == nil || !m.technicalProvisioning {
		return nil, nil
	}
	if inboundTag == "" || m.opJournal == nil {
		return nil, elxjournal.ErrUncertain
	}
	m.subscriptionMu.Lock()
	defer m.subscriptionMu.Unlock()
	if m.store == nil || m.store.failed || m.opJournal.HasPending() {
		return nil, elxjournal.ErrUncertain
	}
	entries, err := m.opJournal.ListTechnicalProfiles()
	if err != nil {
		return nil, err
	}
	recovered := make([]elxjournal.TechnicalProfile, 0)
	for _, p := range entries {
		if p.InboundTag != inboundTag {
			continue
		}
		id, err := uuid.Parse(p.ProfileID)
		if err != nil || id == uuid.Nil {
			return nil, elxjournal.ErrCorrupt
		}
		binding, bound := m.leaseBindings[p.SubscriptionID]
		// Any profile on this specific inbound must remain scoped to the
		// independently pinned node, executor, resource and store version.
		if !bound || p.NodeID != m.leaseNodeID.String() ||
			p.ResourceID != binding.ResourceID.String() ||
			p.ExecutorID != binding.ExecutorID.String() ||
			p.AuthorityGeneration < binding.MinAuthorityGeneration {
			return nil, elxjournal.ErrStale
		}
		switch p.Phase {
		case "INSTALLED":
			policy, known := m.subscriptionPolicies[p.SubscriptionID]
			revision, generation, ready := m.opJournal.ResourceState(p.ResourceID)
			if !known || !ready || policy.Disabled ||
				p.PolicyRevision != policy.Revision ||
				p.PolicyRevision != revision ||
				p.AuthorityGeneration != generation ||
				m.opJournal.DeniedProfiles()[p.ProfileID] != 0 {
				return nil, elxjournal.ErrStale
			}
			recovered = append(recovered, p)
		case "PREPARED":
			// PREPARED never creates a live user. It is safe to keep an old
			// non-admitting pending record for later Control reconciliation.
		case "RETIRED":
			// A tombstone survives, never rehydrate a retired validator user.
			if m.opJournal.DeniedProfiles()[p.ProfileID] != p.RetireGeneration {
				return nil, elxjournal.ErrCorrupt
			}
		default:
			return nil, elxjournal.ErrUncertain
		}
	}
	return recovered, nil
}
