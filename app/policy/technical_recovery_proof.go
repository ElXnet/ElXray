package policy

import (
	"crypto/ed25519"
	"encoding/hex"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common/elxjournal"
	"github.com/xtls/xray-core/common/elxprovision"
)

// recoveryTechnicalProfile verifies a completed and durable local
// technical operation for read-only, post-expiry receipt recovery. A lost
// Control ACK must never require replay of the expired signed mutation.
// A successful recovery is NOT permission to admit device VPN payload.
func (m *Instance) recoveryTechnicalProfile(profileID, operationID, phase string) (elxjournal.TechnicalProfile, error) {
	var empty elxjournal.TechnicalProfile
	if m == nil || !m.technicalProvisioning || m.opJournal == nil ||
		m.store == nil || m.store.failed || len(m.store.key) != ed25519.PrivateKeySize ||
		m.opJournal.HasPending() {
		return empty, elxjournal.ErrUncertain
	}
	id, e1 := uuid.Parse(profileID)
	op, e2 := uuid.Parse(operationID)
	if e1 != nil || e2 != nil || id == uuid.Nil || op == uuid.Nil ||
		id.String() != profileID || op.String() != operationID {
		return empty, elxjournal.ErrInvalid
	}
	record, found := m.opJournal.TechnicalProfile(profileID)
	if !found || record.Phase != phase ||
		record.NodeID != m.leaseNodeID.String() {
		return empty, elxjournal.ErrStale
	}
	binding, bound := m.leaseBindings[record.SubscriptionID]
	if !bound || record.ExecutorID != binding.ExecutorID.String() ||
		record.ResourceID != binding.ResourceID.String() ||
		record.AuthorityGeneration < binding.MinAuthorityGeneration {
		return empty, elxjournal.ErrStale
	}
	switch phase {
	case "INSTALLED":
		if record.InstallOperationID != operationID ||
			record.InstallTranscriptSHA256 == "" ||
			m.opJournal.DeniedProfiles()[profileID] != 0 {
			return empty, elxjournal.ErrStale
		}
	case "RETIRED":
		if record.RetireOperationID != operationID ||
			record.RetireTranscriptSHA256 == "" ||
			record.RetireGeneration != 2 ||
			m.opJournal.DeniedProfiles()[profileID] != record.RetireGeneration {
			return empty, elxjournal.ErrStale
		}
	default:
		return empty, elxjournal.ErrInvalid
	}
	return record, nil
}

// RecoverTechnicalInstalledProof is strictly read-only. The journal's
// immutable accepted signed INSTALL digest is used even after the original
// Control ticket expires. Actual live inbound registration must match.
func (m *Instance) RecoverTechnicalInstalledProof(profileID, operationID string) (elxprovision.InstallReceipt, error) {
	var empty elxprovision.InstallReceipt
	if m == nil {
		return empty, elxjournal.ErrUncertain
	}
	m.subscriptionMu.Lock()
	defer m.subscriptionMu.Unlock()
	record, err := m.recoveryTechnicalProfile(profileID, operationID, "INSTALLED")
	if err != nil {
		return empty, err
	}
	handler, err := m.technicalVLESSHandler(record.InboundTag)
	id := uuid.MustParse(profileID)
	if err != nil || !liveTechnicalUserMatches(handler, record.Email, id, record.Flow) {
		return empty, elxjournal.ErrUncertain
	}
	storeRaw, valid := m.opJournal.StoreIdentity()
	store, parseErr := uuid.Parse(storeRaw)
	boot := uuid.UUID(m.usageIncarnation)
	if !valid || parseErr != nil || store == uuid.Nil || boot == uuid.Nil {
		return empty, elxjournal.ErrCorrupt
	}
	proof := elxprovision.InstallReceipt{
		Version: 1, OperationID: uuid.MustParse(operationID), ProfileID: id,
		NodeID: uuid.MustParse(record.NodeID),
		ResourceID: uuid.MustParse(record.ResourceID),
		ExecutorID: uuid.MustParse(record.ExecutorID),
		StoreID: store, CoreIncarnation: boot,
		AuthorityGeneration: record.AuthorityGeneration,
		PolicyRevision: record.PolicyRevision,
		TranscriptSHA256: record.InstallTranscriptSHA256,
	}
	proof.Signature = ed25519.Sign(m.store.key, proof.Transcript())
	return proof, nil
}

// RecoverTechnicalRetiredProof signs only when the permanent tombstone is
// present and the effective UUID is absent from the actual VLESS validator.
// Neither a missing lease nor ticket expiry authorizes an extra mutation.
func (m *Instance) RecoverTechnicalRetiredProof(profileID, operationID string) (elxprovision.RetireReceipt, error) {
	var empty elxprovision.RetireReceipt
	if m == nil {
		return empty, elxjournal.ErrUncertain
	}
	m.subscriptionMu.Lock()
	defer m.subscriptionMu.Unlock()
	record, err := m.recoveryTechnicalProfile(profileID, operationID, "RETIRED")
	if err != nil {
		return empty, err
	}
	handler, err := m.technicalVLESSHandler(record.InboundTag)
	id := uuid.MustParse(profileID)
	// A previously retired email may already be assigned to a new, distinct
	// effective VLESS UUID. Only the permanently tombstoned UUID must be absent.
	if err != nil || technicalVLESSIdentityPresent(handler, id) {
		return empty, elxjournal.ErrUncertain
	}
	storeRaw, valid := m.opJournal.StoreIdentity()
	store, parseErr := uuid.Parse(storeRaw)
	boot := uuid.UUID(m.usageIncarnation)
	if !valid || parseErr != nil || store == uuid.Nil || boot == uuid.Nil {
		return empty, elxjournal.ErrCorrupt
	}
	// The digest is bound to the accepted, signed RETIRE operation; the
	// node cannot manufacture new Control authority using a readback.
	if bytes, err := hex.DecodeString(record.RetireTranscriptSHA256); err != nil || len(bytes) != 32 {
		return empty, elxjournal.ErrCorrupt
	}
	proof := elxprovision.RetireReceipt{
		Version: 1, OperationID: uuid.MustParse(operationID), ProfileID: id,
		NodeID: uuid.MustParse(record.NodeID),
		ResourceID: uuid.MustParse(record.ResourceID),
		ExecutorID: uuid.MustParse(record.ExecutorID),
		StoreID: store, CoreIncarnation: boot,
		AuthorityGeneration: record.AuthorityGeneration,
		PolicyRevision: record.PolicyRevision,
		RetireGeneration: record.RetireGeneration,
		TranscriptSHA256: record.RetireTranscriptSHA256,
	}
	proof.Signature = ed25519.Sign(m.store.key, proof.Transcript())
	return proof, nil
}
