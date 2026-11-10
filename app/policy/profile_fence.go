package policy

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/features/policy"
)

// RegisterVLESSProfile registers a real authenticated VLESS account UUID.
// The inbound calls this during configuration and dynamic user provisioning.
func (m *Instance) RegisterVLESSProfile(id uuid.UUID) {
	m.profileGate.Register([16]byte(id))
}

// TrackVLESSProfile admits one authenticated VLESS flow. Atomic denial blocks
// both newly authenticated connections and attempts to reopen a drained one.
func (m *Instance) TrackVLESSProfile(id uuid.UUID, stop func()) (func(), error) {
	return m.profileGate.Track([16]byte(id), stop)
}

// DrainVLESSProfile durably disables one VLESS profile, asks all active flows
// to close, and signs ONLY after each authenticated inbound has returned.
// It never signs when the core cannot persist denial, a flow remains open,
// or the caller supplies an incarnation other than this running core's boot.
func (m *Instance) DrainVLESSProfile(ctx context.Context, request policy.ProfileDrainRequest) ([]byte, error) {
	if request.OwnerID == uuid.Nil || request.ProfileID == uuid.Nil ||
		request.NodeID == uuid.Nil || request.Incarnation == uuid.Nil ||
		request.Generation <= 0 {
		return nil, errors.New("invalid profile drain identity")
	}
	m.subscriptionMu.Lock()
	if m.store == nil || m.store.failed || m.usageIncarnation != [16]byte(request.Incarnation) {
		m.subscriptionMu.Unlock()
		return nil, errors.New("durable ElXray session drain unavailable")
	}
	// Persist an immutable profile-denial tombstone BEFORE issuing the
	// in-memory drain. A v2 snapshot restored without this tombstone must
	// never reactivate a VLESS profile previously denied by Control.
	if m.opJournal != nil {
		if err := m.opJournal.RecordDeniedProfile(request.ProfileID.String(), uint64(request.Generation)); err != nil {
			m.store.failed = true
			m.subscriptionMu.Unlock()
			return nil, fmt.Errorf("cannot persist managed profile tombstone: %w", err)
		}
	}
	stops, err := m.profileGate.Deny([16]byte(request.ProfileID))
	if err != nil {
		m.subscriptionMu.Unlock()
		return nil, err
	}
	// The in-memory deny gate is installed before persistence: new VLESS flows
	// cannot sneak in between the durable write and active-flow shutdown.
	if err := m.store.write(m.subscriptionPolicies, m.profileGate.Denied()); err != nil {
		m.store.failed = true
		m.subscriptionMu.Unlock()
		return nil, fmt.Errorf("cannot persist profile denial: %w", err)
	}
	m.subscriptionMu.Unlock()
	for _, stop := range stops {
		stop()
	}
	if err := m.profileGate.Wait(ctx, [16]byte(request.ProfileID)); err != nil {
		// Denial stays durable; retry is safe. Never sign incomplete drain.
		return nil, err
	}
	m.subscriptionMu.Lock()
	defer m.subscriptionMu.Unlock()
	if m.store == nil || m.store.failed || !m.profileGate.IsDenied([16]byte(request.ProfileID)) ||
		m.usageIncarnation != [16]byte(request.Incarnation) {
		return nil, errors.New("profile drain durability lost")
	}
	message := []byte("elx-session-fence-v2\x00")
	message = append(message, request.OwnerID[:]...)
	message = binary.BigEndian.AppendUint64(message, uint64(request.Generation))
	message = append(message, request.NodeID[:]...)
	message = append(message, request.Incarnation[:]...)
	message = append(message, request.ProfileID[:]...)
	return ed25519.Sign(m.store.key, message), nil
}
