package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common/elxjournal"
	"github.com/xtls/xray-core/common/elxprovision"
	"github.com/xtls/xray-core/proxy/vless"
)

// RetireTechnicalProfile is a second independently signed v2 operation.
// It denies the effective VLESS identity in the durable journal BEFORE
// attempting any live mutation. An interrupted removal leaves RETIRING and
// prevents a managed restart; no owner slot is ever released on this path.
// A valid signed revocation may run after paid lease expiry (removal does not
// grant capacity), but requires the exact pinned current authority generation.
func (m *Instance) RetireTechnicalProfile(raw []byte) (elxjournal.TechnicalProfile, error) {
	empty := elxjournal.TechnicalProfile{}
	if m == nil || !m.technicalProvisioning || m.opJournal == nil ||
		len(m.leasePublicKey) == 0 || len(raw) == 0 || len(raw) > 4096 {
		return empty, elxprovision.ErrUnauthorized
	}
	var selector struct {
		Grant struct { SubscriptionID string }
	}
	if err := json.Unmarshal(raw, &selector); err != nil ||
		selector.Grant.SubscriptionID == "" {
		return empty, elxprovision.ErrInvalid
	}
	m.subscriptionMu.Lock()
	defer m.subscriptionMu.Unlock()
	binding, ok := m.leaseBindings[selector.Grant.SubscriptionID]
	if !ok || binding.ResourceID == uuid.Nil || binding.ExecutorID == uuid.Nil {
		return empty, elxprovision.ErrUnauthorized
	}
	grant, err := elxprovision.DecodeControlJob(raw, m.leasePublicKey,
		m.leaseNodeID, binding.ExecutorID, binding.ResourceID, time.Now().UTC())
	if err != nil {
		return empty, err
	}
	if grant.Version != 2 || grant.Action != elxprovision.Retire ||
		grant.ProfileGeneration != 2 || grant.AuthorityGeneration < binding.MinAuthorityGeneration {
		return empty, elxprovision.ErrUnauthorized
	}
	previous, ok := m.opJournal.TechnicalProfile(grant.ProfileID.String())
	if !ok || previous.NodeID != grant.NodeID.String() ||
		previous.ExecutorID != grant.ExecutorID.String() ||
		previous.ResourceID != grant.ResourceID.String() ||
		previous.SubscriptionID != grant.SubscriptionID ||
		previous.InboundTag != grant.InboundTag ||
		previous.Email != grant.Email ||
		previous.Flow != grant.Flow ||
		previous.AuthorityGeneration != grant.AuthorityGeneration ||
		previous.PolicyRevision != grant.PolicyRevision ||
		previous.ProfileGeneration+1 != grant.ProfileGeneration {
		return empty, elxjournal.ErrStale
	}
	revision, generation, ready := m.opJournal.ResourceState(grant.ResourceID.String())
	if !ready || revision != grant.PolicyRevision ||
		generation != grant.AuthorityGeneration || m.store == nil || m.store.failed {
		return empty, elxjournal.ErrStale
	}
	handler, err := m.technicalVLESSHandler(grant.InboundTag)
	if err != nil {
		return empty, elxjournal.ErrUncertain
	}
	digest := sha256.Sum256(grant.Transcript())
	digestHex := hex.EncodeToString(digest[:])
	if previous.Phase == "RETIRED" {
		if previous.RetireOperationID != grant.OperationID.String() ||
			previous.RetireTranscriptSHA256 != digestHex ||
			m.opJournal.DeniedProfiles()[grant.ProfileID.String()] < grant.ProfileGeneration {
			return empty, elxjournal.ErrCollision
		}
		if technicalVLESSIdentityPresent(handler, grant.ProfileID) {
			return empty, elxjournal.ErrUncertain
		}
		return previous, nil
	}
	// A PREPARED profile can have no legitimate dynamic user; if the same
	// UUID is live from static JSON, the signed RETIRE must quarantine,
	// never remove a user whose creation we cannot prove.
	hasLiveUser := liveTechnicalUserMatches(handler, grant.Email, grant.ProfileID, grant.Flow)
	if previous.Phase == "PREPARED" && technicalVLESSIdentityPresent(handler, grant.ProfileID) {
		return empty, elxjournal.ErrCollision
	}
	if previous.Phase == "INSTALLED" && technicalVLESSIdentityPresent(handler, grant.ProfileID) &&
		!hasLiveUser {
		return empty, elxjournal.ErrCollision
	}
	if _, err := m.opJournal.BeginTechnicalRetire(grant.ProfileID.String(),
		grant.OperationID.String(), digestHex, grant.ProfileGeneration,
		grant.PolicyRevision, grant.AuthorityGeneration); err != nil {
		return empty, err
	}
	// Failure after this point is uncertain: tombstone persists but the live
	// account might have been removed or retained. Operator must reconcile.
	if hasLiveUser {
		if err := handler.RemoveUser(m.runtimeContext, grant.Email); err != nil {
			m.store.failed = true
			return empty, elxjournal.ErrUncertain
		}
	}
	if technicalVLESSIdentityPresent(handler, grant.ProfileID) ||
		handler.GetUser(nil, grant.Email) != nil {
		m.store.failed = true
		return empty, elxjournal.ErrUncertain
	}
	done, err := m.opJournal.MarkTechnicalRetired(grant.ProfileID.String(), grant.OperationID.String())
	if err != nil {
		m.store.failed = true
		return empty, elxjournal.ErrUncertain
	}
	return done, nil
}

// technicalVLESSIdentityPresent examines the actual authenticated UUID map.
// A renamed email or a ProcessUUID alias must never be mistaken for removal.
func technicalVLESSIdentityPresent(handler technicalVLESSUserManager, profileID uuid.UUID) bool {
	if handler == nil {
		return true // unknown must never be treated as absent
	}
	target := vless.ProcessUUID([16]byte(profileID))
	for _, user := range handler.GetUsers(nil) {
		if user == nil {
			return true
		}
		account, ok := user.Account.(*vless.MemoryAccount)
		if !ok || account == nil || account.ID == nil {
			return true
		}
		if vless.ProcessUUID(account.ID.UUID()) == target {
			return true
		}
	}
	return false
}
