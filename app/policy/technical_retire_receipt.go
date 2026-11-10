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

// SignedTechnicalRetireReceipt attests only a permanently tombstoned
// technical VLESS account and the absence of its effective UUID from the
// *actual* inbound. It is not a signed device release or session drain.
func (m *Instance) SignedTechnicalRetireReceipt(raw []byte) (elxprovision.RetireReceipt, error) {
	empty := elxprovision.RetireReceipt{}
	if m == nil || !m.technicalProvisioning || m.opJournal == nil ||
		len(m.leasePublicKey) != ed25519.PublicKeySize ||
		len(raw) == 0 || len(raw) > 4096 {
		return empty, elxprovision.ErrUnauthorized
	}
	var selector struct {
		Grant struct { SubscriptionID string }
	}
	if json.Unmarshal(raw, &selector) != nil || selector.Grant.SubscriptionID == "" {
		return empty, elxprovision.ErrInvalid
	}
	m.subscriptionMu.Lock()
	defer m.subscriptionMu.Unlock()
	binding, ok := m.leaseBindings[selector.Grant.SubscriptionID]
	if !ok || binding.ExecutorID == uuid.Nil || binding.ResourceID == uuid.Nil {
		return empty, elxprovision.ErrUnauthorized
	}
	g, err := elxprovision.DecodeControlJob(raw, m.leasePublicKey, m.leaseNodeID,
		binding.ExecutorID, binding.ResourceID, time.Now().UTC())
	if err != nil {
		return empty, err
	}
	if g.Version != 2 || g.Action != elxprovision.Retire || g.ProfileGeneration != 2 ||
		g.AuthorityGeneration < binding.MinAuthorityGeneration || m.store == nil ||
		m.store.failed || len(m.store.key) != ed25519.PrivateKeySize {
		return empty, elxprovision.ErrUnauthorized
	}
	record, found := m.opJournal.TechnicalProfile(g.ProfileID.String())
	hash := sha256.Sum256(g.Transcript())
	digest := hex.EncodeToString(hash[:])
	if !found || record.Phase != "RETIRED" ||
		record.RetireGeneration != g.ProfileGeneration ||
		record.RetireOperationID != g.OperationID.String() ||
		record.RetireTranscriptSHA256 != digest ||
		record.NodeID != g.NodeID.String() ||
		record.ExecutorID != g.ExecutorID.String() ||
		record.ResourceID != g.ResourceID.String() ||
		record.SubscriptionID != g.SubscriptionID ||
		record.Email != g.Email || record.InboundTag != g.InboundTag ||
		record.Flow != g.Flow || record.PolicyRevision != g.PolicyRevision ||
		record.AuthorityGeneration != g.AuthorityGeneration ||
		m.opJournal.DeniedProfiles()[g.ProfileID.String()] != g.ProfileGeneration ||
		m.opJournal.HasPending() {
		return empty, elxjournal.ErrUncertain
	}
	handler, err := m.technicalVLESSHandler(g.InboundTag)
	if err != nil || technicalVLESSIdentityPresent(handler, g.ProfileID) ||
		handler.GetUser(nil, g.Email) != nil {
		return empty, elxjournal.ErrUncertain
	}
	storeString, good := m.opJournal.StoreIdentity()
	if !good {
		return empty, elxjournal.ErrCorrupt
	}
	storeID, err := uuid.Parse(storeString)
	if err != nil || storeID == uuid.Nil {
		return empty, elxjournal.ErrCorrupt
	}
	boot := uuid.UUID(m.usageIncarnation)
	if boot == uuid.Nil {
		return empty, elxjournal.ErrUncertain
	}
	proof := elxprovision.RetireReceipt{
		Version: 1, OperationID: g.OperationID, ProfileID: g.ProfileID,
		NodeID: g.NodeID, ExecutorID: g.ExecutorID, ResourceID: g.ResourceID,
		StoreID: storeID, CoreIncarnation: boot, AuthorityGeneration: g.AuthorityGeneration,
		PolicyRevision: g.PolicyRevision, RetireGeneration: g.ProfileGeneration,
		TranscriptSHA256: digest,
	}
	proof.Signature = ed25519.Sign(m.store.key, proof.Transcript())
	return proof, nil
}
