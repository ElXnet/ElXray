package policy

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common/elxjournal"
	"github.com/xtls/xray-core/common/elxprovision"
)

// SignedTechnicalInstallReceipt is the ONLY Stage-4 primitive allowed to
// attest that a technical VLESS identity exists in this running core.
// The caller supplies a Control-signed INSTALL, not profile fields or a key.
// This does NOT authorize VPN payload or a device ownership/slot transition.
func (m *Instance) SignedTechnicalInstallReceipt(raw []byte) (elxprovision.InstallReceipt, error) {
	var empty elxprovision.InstallReceipt
	if m == nil || !m.technicalProvisioning || m.opJournal == nil ||
		len(m.leasePublicKey) != ed25519.PublicKeySize ||
		len(raw) == 0 || len(raw) > 4096 {
		return empty, elxprovision.ErrUnauthorized
	}
	var selector struct {
		Grant struct {
			SubscriptionID string
		}
	}
	if err := json.Unmarshal(raw, &selector); err != nil ||
		selector.Grant.SubscriptionID == "" {
		return empty, elxprovision.ErrInvalid
	}
	m.subscriptionMu.Lock()
	defer m.subscriptionMu.Unlock()
	binding, ok := m.leaseBindings[selector.Grant.SubscriptionID]
	if !ok || binding.ExecutorID == uuid.Nil || binding.ResourceID == uuid.Nil {
		return empty, elxprovision.ErrUnauthorized
	}
	now := time.Now().UTC()
	grant, err := elxprovision.DecodeControlJob(raw, m.leasePublicKey,
		m.leaseNodeID, binding.ExecutorID, binding.ResourceID, now)
	if err != nil {
		return empty, err
	}
	if grant.Version != 2 || grant.Action != elxprovision.Install ||
		grant.ProfileGeneration != 1 ||
		grant.AuthorityGeneration < binding.MinAuthorityGeneration {
		return empty, elxprovision.ErrUnauthorized
	}
	lease, leased := m.leaseAccepted[grant.SubscriptionID]
	policy, known := m.subscriptionPolicies[grant.SubscriptionID]
	revision, generation, ready := m.opJournal.ResourceState(grant.ResourceID.String())
	if !leased || !known || !ready || policy.Disabled || m.store == nil ||
		m.store.failed || len(m.store.key) != ed25519.PrivateKeySize ||
		lease.NotAfter <= now.Unix() ||
		lease.NodeID != grant.NodeID || lease.ExecutorID != grant.ExecutorID ||
		lease.ResourceID != grant.ResourceID ||
		lease.AuthorityGeneration != grant.AuthorityGeneration ||
		revision != grant.PolicyRevision || generation != grant.AuthorityGeneration ||
		policy.Revision != grant.PolicyRevision {
		return empty, elxjournal.ErrStale
	}
	record, found := m.opJournal.TechnicalProfile(grant.ProfileID.String())
	hash := sha256.Sum256(grant.Transcript())
	digest := hex.EncodeToString(hash[:])
	if !found || record.Phase != "INSTALLED" ||
		record.InstallOperationID != grant.OperationID.String() ||
		record.InstallTranscriptSHA256 != digest ||
		record.InboundTag != grant.InboundTag ||
		record.Email != grant.Email || record.Flow != grant.Flow ||
		record.ProfileID != grant.ProfileID.String() ||
		record.ExecutorID != grant.ExecutorID.String() ||
		record.ResourceID != grant.ResourceID.String() ||
		record.NodeID != grant.NodeID.String() ||
		record.SubscriptionID != grant.SubscriptionID ||
		record.AuthorityGeneration != grant.AuthorityGeneration ||
		record.PolicyRevision != grant.PolicyRevision ||
		m.opJournal.HasPending() {
		return empty, elxjournal.ErrUncertain
	}
	handler, err := m.technicalVLESSHandler(grant.InboundTag)
	if err != nil || !liveTechnicalUserMatches(handler, grant.Email, grant.ProfileID, grant.Flow) {
		return empty, elxjournal.ErrUncertain
	}
	storeID, good := m.opJournal.StoreIdentity()
	if !good {
		return empty, elxjournal.ErrCorrupt
	}
	stableStore, err := uuid.Parse(storeID)
	if err != nil || stableStore == uuid.Nil {
		return empty, elxjournal.ErrCorrupt
	}
	incarnation := uuid.UUID(m.usageIncarnation)
	if incarnation == uuid.Nil {
		return empty, elxjournal.ErrUncertain
	}
	proof := elxprovision.InstallReceipt{
		Version: 1, OperationID: grant.OperationID, ProfileID: grant.ProfileID,
		NodeID: grant.NodeID, ExecutorID: grant.ExecutorID, ResourceID: grant.ResourceID,
		StoreID: stableStore, CoreIncarnation: incarnation,
		AuthorityGeneration: grant.AuthorityGeneration, PolicyRevision: grant.PolicyRevision,
		TranscriptSHA256: digest,
	}
	proof.Signature = ed25519.Sign(m.store.key, proof.Transcript())
	return proof, nil
}
