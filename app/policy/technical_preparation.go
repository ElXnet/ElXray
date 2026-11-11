package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common/elxjournal"
	"github.com/xtls/xray-core/common/elxprovision"
)

// PrepareTechnicalProfile accepts a short-lived, Control-signed, exact-executor
// PREPARE intent over the local Unix Commander. It is deliberately NOT an
// AddUser operation: a durable prepared VLESS UUID is not an admitted device.
// The caller must be authenticated by the kernel peercred gRPC transport.
// Nothing here may change a VLESS inbound, owner slot or live rate.
func (m *Instance) PrepareTechnicalProfile(raw []byte) (elxjournal.TechnicalProfile, error) {
	if m == nil || !m.technicalProvisioning || m.opJournal == nil ||
		len(m.leasePublicKey) == 0 || len(raw) == 0 || len(raw) > 4096 {
		return elxjournal.TechnicalProfile{}, elxprovision.ErrUnauthorized
	}

	// Untrusted JSON is used ONLY to find the independently pinned binding.
	// DecodeControlJob below rejects all unknown fields, trailing data,
	// duplicated/nested signature formats and any unsigned mutation.
	var selector struct {
		Grant struct {
			SubscriptionID string
		}
	}
	if err := json.Unmarshal(raw, &selector); err != nil ||
		selector.Grant.SubscriptionID == "" {
		return elxjournal.TechnicalProfile{}, elxprovision.ErrInvalid
	}

	m.subscriptionMu.Lock()
	defer m.subscriptionMu.Unlock()
	binding, ok := m.leaseBindings[selector.Grant.SubscriptionID]
	if !ok || binding.ResourceID == uuid.Nil || binding.ExecutorID == uuid.Nil {
		return elxjournal.TechnicalProfile{}, elxprovision.ErrUnauthorized
	}
	now := time.Now().UTC()
	g, err := elxprovision.DecodeControlJob(raw, m.leasePublicKey,
		m.leaseNodeID, binding.ExecutorID, binding.ResourceID, now)
	if err != nil {
		return elxjournal.TechnicalProfile{}, err
	}
	if g.Action != elxprovision.Prepare || g.ProfileGeneration != 1 ||
		g.AuthorityGeneration < binding.MinAuthorityGeneration {
		return elxjournal.TechnicalProfile{}, elxprovision.ErrUnauthorized
	}
	activeLease, leased := m.leaseAccepted[g.SubscriptionID]
	policy, known := m.subscriptionPolicies[g.SubscriptionID]
	revision, generation, ready := m.opJournal.ResourceState(g.ResourceID.String())
	if !leased || !known || !ready || m.store == nil || m.store.failed ||
		activeLease.NotAfter <= now.Unix() ||
		activeLease.AuthorityGeneration != g.AuthorityGeneration ||
		activeLease.NodeID != g.NodeID || activeLease.ExecutorID != g.ExecutorID ||
		activeLease.ResourceID != g.ResourceID ||
		revision != g.PolicyRevision || generation != g.AuthorityGeneration ||
		policy.Revision != g.PolicyRevision || policy.Disabled {
		return elxjournal.TechnicalProfile{}, elxjournal.ErrStale
	}
	sum := sha256.Sum256(g.Transcript())
	prepared := elxjournal.TechnicalProfile{
		ProfileID: g.ProfileID.String(), OperationID: g.OperationID.String(),
		NodeID: g.NodeID.String(), ResourceID: g.ResourceID.String(),
		ExecutorID:     g.ExecutorID.String(),
		SubscriptionID: g.SubscriptionID, Email: g.Email,
		InboundTag: g.InboundTag, ProfileGeneration: g.ProfileGeneration,
		AuthorityGeneration: g.AuthorityGeneration,
		PolicyRevision:      g.PolicyRevision, NotAfterUnix: g.NotAfter,
		TranscriptSHA256: hex.EncodeToString(sum[:]), Phase: "PREPARED",
	}
	if err := m.opJournal.RecordTechnicalPrepared(prepared); err != nil {
		return elxjournal.TechnicalProfile{}, err
	}
	return prepared, nil
}

// TechnicalProfileReadback is local state only. It is NOT a core-signed
// installed receipt and MUST NOT cause Control to mark INTENT as APPLIED.
func (m *Instance) TechnicalProfileReadback(profileID string) (elxjournal.TechnicalProfile, error) {
	if m == nil || !m.technicalProvisioning || m.opJournal == nil {
		return elxjournal.TechnicalProfile{}, elxjournal.ErrInvalid
	}
	id, err := uuid.Parse(profileID)
	if err != nil || id == uuid.Nil || id.String() != profileID {
		return elxjournal.TechnicalProfile{}, elxjournal.ErrInvalid
	}
	// Readback must not race a signed INSTALL or RETIRE. Its live VLESS
	// identity scan shares the same lock as the mutation and receipt paths.
	m.subscriptionMu.Lock()
	defer m.subscriptionMu.Unlock()
	profile, found := m.opJournal.TechnicalProfile(profileID)
	if !found {
		return elxjournal.TechnicalProfile{}, errors.New("technical VLESS profile not prepared")
	}
	if profile.Phase == "INSTALLED" {
		// On restart the journal alone cannot prove the user has actually
		// been registered in this running VLESS inbound incarnation.
		handler, err := m.technicalVLESSHandler(profile.InboundTag)
		if err != nil {
			return elxjournal.TechnicalProfile{}, elxjournal.ErrUncertain
		}
		id := uuid.MustParse(profile.ProfileID)
		if !liveTechnicalUserMatches(handler, profile.Email, id, profile.Flow) {
			return elxjournal.TechnicalProfile{}, elxjournal.ErrUncertain
		}
		if err := m.verifyTechnicalVLESSScope(profile.InboundTag, profile.Email, id, true); err != nil {
			return elxjournal.TechnicalProfile{}, elxjournal.ErrUncertain
		}
	} else if profile.Phase == "RETIRED" {
		id := uuid.MustParse(profile.ProfileID)
		if err := m.verifyTechnicalVLESSScope(profile.InboundTag, profile.Email, id, false); err != nil {
			return elxjournal.TechnicalProfile{}, elxjournal.ErrUncertain
		}
	}
	return profile, nil
}
