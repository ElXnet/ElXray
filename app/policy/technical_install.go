package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common/elxjournal"
	"github.com/xtls/xray-core/common/elxprovision"
	"github.com/xtls/xray-core/common/protocol"
	xrayuuid "github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	inboundfeature "github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/proxy/vless"
)

// technicalVLESSUserManager matches only the minimal methods required by
// signed technical installation. It deliberately avoids importing proxy,
// whose dispatcher dependency would create a package import cycle.
type technicalVLESSUserManager interface {
	AddUser(context.Context, *protocol.MemoryUser) error
	RemoveUser(context.Context, string) error
	GetUser(context.Context, string) *protocol.MemoryUser
	GetUsers(context.Context) []*protocol.MemoryUser
}

// technicalVLESSHandler resolves only an existing, exact-tag VLESS inbound.
// It deliberately cannot add/remove inbound listeners or mutate a non-VLESS
// handler. The legacy HandlerService/AddUser path remains denied in managed mode.
func (m *Instance) technicalVLESSHandler(tag string) (technicalVLESSUserManager, error) {
	if m == nil || m.runtimeContext == nil {
		return nil, elxjournal.ErrUncertain
	}
	server := core.FromContext(m.runtimeContext)
	if server == nil {
		return nil, elxjournal.ErrUncertain
	}
	manager, ok := server.GetFeature(inboundfeature.ManagerType()).(inboundfeature.Manager)
	if !ok {
		return nil, elxjournal.ErrUncertain
	}
	handler, err := manager.GetHandler(m.runtimeContext, tag)
	if err != nil {
		return nil, elxjournal.ErrStale
	}
	getter, ok := handler.(interface{ ElXVLESSTechnicalUsers() any })
	if !ok {
		return nil, elxjournal.ErrInvalid
	}
	users, ok := getter.ElXVLESSTechnicalUsers().(technicalVLESSUserManager)
	if !ok {
		return nil, elxjournal.ErrInvalid
	}
	return users, nil
}

func liveTechnicalUserMatches(handler technicalVLESSUserManager, email string, id uuid.UUID, flow string) bool {
	if handler == nil {
		return false
	}
	user := handler.GetUser(nil, email)
	if user == nil || user.Email != email {
		return false
	}
	account, ok := user.Account.(*vless.MemoryAccount)
	return ok && account != nil && account.ID != nil &&
		uuid.UUID(account.ID.UUID()) == id && account.Flow == flow
}

// InstallTechnicalProfile is a dedicated signed v2 operation. A PREPARE is NOT
// sufficient authorization to create a live VLESS user. All checks happen
// under the subscription lock before durable INSTALLING is recorded. The new
// user is still NEVER admitted to payload: separate device/owner proof remains
// mandatory and is deliberately not implemented in Stage 4.
func (m *Instance) InstallTechnicalProfile(raw []byte) (elxjournal.TechnicalProfile, error) {
	if m == nil || !m.technicalProvisioning || m.opJournal == nil ||
		len(m.leasePublicKey) == 0 || len(raw) == 0 || len(raw) > 4096 {
		return elxjournal.TechnicalProfile{}, elxprovision.ErrUnauthorized
	}
	var selector struct {
		Grant struct {
			SubscriptionID string
		}
	}
	if err := json.Unmarshal(raw, &selector); err != nil || selector.Grant.SubscriptionID == "" {
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
	if g.Version != 2 || g.Action != elxprovision.Install ||
		g.ProfileGeneration != 1 || g.AuthorityGeneration < binding.MinAuthorityGeneration {
		return elxjournal.TechnicalProfile{}, elxprovision.ErrUnauthorized
	}
	lease, leased := m.leaseAccepted[g.SubscriptionID]
	sub, known := m.subscriptionPolicies[g.SubscriptionID]
	revision, generation, ready := m.opJournal.ResourceState(g.ResourceID.String())
	if !leased || !known || !ready || m.store == nil || m.store.failed ||
		lease.NotAfter <= now.Unix() || lease.AuthorityGeneration != g.AuthorityGeneration ||
		lease.NodeID != g.NodeID || lease.ExecutorID != g.ExecutorID ||
		lease.ResourceID != g.ResourceID ||
		revision != g.PolicyRevision || generation != g.AuthorityGeneration ||
		sub.Revision != g.PolicyRevision || sub.Disabled {
		return elxjournal.TechnicalProfile{}, elxjournal.ErrStale
	}
	prepared, exists := m.opJournal.TechnicalProfile(g.ProfileID.String())
	if !exists || prepared.NodeID != g.NodeID.String() ||
		prepared.ResourceID != g.ResourceID.String() ||
		prepared.ExecutorID != g.ExecutorID.String() ||
		prepared.SubscriptionID != g.SubscriptionID ||
		prepared.Email != g.Email || prepared.InboundTag != g.InboundTag ||
		prepared.ProfileGeneration != g.ProfileGeneration ||
		prepared.AuthorityGeneration != g.AuthorityGeneration ||
		prepared.PolicyRevision != g.PolicyRevision {
		return elxjournal.TechnicalProfile{}, elxjournal.ErrStale
	}
	handler, err := m.technicalVLESSHandler(g.InboundTag)
	if err != nil {
		return elxjournal.TechnicalProfile{}, err
	}
	digest := sha256.Sum256(g.Transcript())
	digestHex := hex.EncodeToString(digest[:])
	if prepared.Phase == "INSTALLED" &&
		prepared.InstallOperationID == g.OperationID.String() &&
		prepared.InstallTranscriptSHA256 == digestHex &&
		liveTechnicalUserMatches(handler, g.Email, g.ProfileID, g.Flow) {
		if err := m.verifyTechnicalVLESSScope(g.InboundTag, g.Email, g.ProfileID, true); err != nil {
			return elxjournal.TechnicalProfile{}, err
		}
		return prepared, nil // exact idempotent retry, all inbounds verified
	}
	if prepared.Phase != "PREPARED" {
		return elxjournal.TechnicalProfile{}, elxjournal.ErrUncertain
	}
	// Reject aliases and shadow users in ALL live VLESS inbound validators,
	// not just the target tag. This check precedes the fsynced INSTALLING
	// state; a collision never creates a partially installed technical user.
	if err := m.verifyTechnicalVLESSScope(g.InboundTag, g.Email, g.ProfileID, false); err != nil {
		return elxjournal.TechnicalProfile{}, err
	}
	// Detect collisions with preconfigured VLESS identities *before* the
	// durable INSTALLING intent. Validator.Add still serializes the final
	// check against racing additions and refuses normalized UUID aliases.
	normalized := vless.ProcessUUID(xrayuuid.UUID(g.ProfileID))
	for _, existing := range handler.GetUsers(nil) {
		account, ok := existing.Account.(*vless.MemoryAccount)
		if !ok || account == nil || account.ID == nil {
			return elxjournal.TechnicalProfile{}, elxjournal.ErrCollision
		}
		if existing.Email == g.Email ||
			vless.ProcessUUID(account.ID.UUID()) == normalized {
			return elxjournal.TechnicalProfile{}, elxjournal.ErrCollision
		}
	}
	if handler.GetUser(nil, g.Email) != nil {
		return elxjournal.TechnicalProfile{}, elxjournal.ErrCollision
	}
	if _, err := m.opJournal.BeginTechnicalInstall(g.ProfileID.String(),
		g.OperationID.String(), digestHex, g.Flow, g.PolicyRevision, g.AuthorityGeneration); err != nil {
		return elxjournal.TechnicalProfile{}, err
	}
	// A crash here leaves INSTALLING and the next managed boot refuses to
	// claim a safe outcome; no fallback to static JSON or unsigned AddUser.
	user := &protocol.MemoryUser{
		Email: g.Email,
		Account: &vless.MemoryAccount{
			ID:   protocol.NewID(xrayuuid.UUID(g.ProfileID)),
			Flow: g.Flow,
		},
	}
	if err := handler.AddUser(m.runtimeContext, user); err != nil {
		m.store.failed = true
		return elxjournal.TechnicalProfile{}, elxjournal.ErrUncertain
	}
	if !liveTechnicalUserMatches(handler, g.Email, g.ProfileID, g.Flow) {
		m.store.failed = true
		_ = handler.RemoveUser(m.runtimeContext, g.Email)
		return elxjournal.TechnicalProfile{}, elxjournal.ErrUncertain
	}
	// A concurrent inbound reload must not make a shadow identity legitimate.
	// Any conflict leaves INSTALLING quarantined rather than marking success.
	if err := m.verifyTechnicalVLESSScope(g.InboundTag, g.Email, g.ProfileID, true); err != nil {
		m.store.failed = true
		_ = handler.RemoveUser(m.runtimeContext, g.Email)
		return elxjournal.TechnicalProfile{}, elxjournal.ErrUncertain
	}
	installed, err := m.opJournal.MarkTechnicalInstalled(g.ProfileID.String(), g.OperationID.String())
	if err != nil {
		m.store.failed = true
		_ = handler.RemoveUser(m.runtimeContext, g.Email)
		return elxjournal.TechnicalProfile{}, elxjournal.ErrUncertain
	}
	return installed, nil // no Control APPLIED ACK or owner admission
}
