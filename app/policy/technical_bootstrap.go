package policy

import (
	"github.com/google/uuid"
	"github.com/xtls/xray-core/common/elxjournal"
	"github.com/xtls/xray-core/common/protocol"
	xrayuuid "github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/vless"
)

// validateTechnicalVLESSBootstrap refuses a static VLESS user that
// impersonates any durable technical profile, including a PREPARED profile
// that has never been installed, or a RETIRED UUID protected by a tombstone.
//
// All inbounds call this before constructing listeners. Checking by the
// effective VLESS authentication key, rather than printed UUID or email,
// protects aliases whose differing bytes are ignored by VLESS lookup.
// The caller separately rehydrates INSTALLED profiles from the journal.
func validateTechnicalVLESSBootstrap(
	staticUsers []*protocol.MemoryUser,
	profiles []elxjournal.TechnicalProfile,
	denied map[string]uint64,
) error {
	reserved := make(map[[16]byte]string, len(profiles)+len(denied))
	for _, profile := range profiles {
		id, err := uuid.Parse(profile.ProfileID)
		if err != nil || id == uuid.Nil || id.String() != profile.ProfileID {
			return elxjournal.ErrCorrupt
		}
		effective := vless.ProcessUUID(xrayuuid.UUID(id))
		if _, duplicate := reserved[effective]; duplicate {
			return elxjournal.ErrCollision
		}
		reserved[effective] = profile.ProfileID
	}
	for raw, generation := range denied {
		id, err := uuid.Parse(raw)
		if err != nil || id == uuid.Nil || id.String() != raw || generation == 0 {
			return elxjournal.ErrCorrupt
		}
		// A retired technical profile legitimately appears in BOTH the
		// journal and denial set. However, another printed UUID with the
		// same effective VLESS key is still a forbidden alias.
		effective := vless.ProcessUUID(xrayuuid.UUID(id))
		if original, exists := reserved[effective]; exists && original != raw {
			return elxjournal.ErrCollision
		}
		reserved[effective] = raw
	}
	for _, user := range staticUsers {
		if user == nil {
			return elxjournal.ErrUncertain
		}
		account, ok := user.Account.(*vless.MemoryAccount)
		if !ok || account == nil || account.ID == nil {
			return elxjournal.ErrUncertain
		}
		if _, reservedKey := reserved[vless.ProcessUUID(account.ID.UUID())]; reservedKey {
			return elxjournal.ErrCollision
		}
	}
	return nil
}

// ValidateTechnicalVLESSBootstrap is the fail-closed managed-core startup
// boundary for static VLESS users. It does not grant any owner/device right.
// Standalone and Stage-2 configurations retain their existing behavior.
func (m *Instance) ValidateTechnicalVLESSBootstrap(users []*protocol.MemoryUser) error {
	if m == nil {
		return elxjournal.ErrInvalid
	}
	if !m.technicalProvisioning {
		return nil
	}
	m.subscriptionMu.Lock()
	defer m.subscriptionMu.Unlock()
	if m.opJournal == nil || m.store == nil || m.store.failed ||
		m.opJournal.HasPending() {
		return elxjournal.ErrUncertain
	}
	profiles, err := m.opJournal.ListTechnicalProfiles()
	if err != nil {
		return err
	}
	return validateTechnicalVLESSBootstrap(users, profiles, m.opJournal.DeniedProfiles())
}


// validateTechnicalInboundRegistration is the last admission check before
// publishing a handler. The constructed VLESS user set already includes
// journal-rehydrated INSTALLED identities. Only that exact user may be
// present on its own assigned inbound; PREPARED, RETIRED and effective UUID
// aliases are never static exceptions.
func validateTechnicalInboundRegistration(tag string, isVLESS bool,
	users []*protocol.MemoryUser, profiles []elxjournal.TechnicalProfile,
	denied map[string]uint64,
) error {
	if err := validateTechnicalVLESSBootstrap(nil, profiles, denied); err != nil {
		return err
	}
	owners := make(map[[16]byte]elxjournal.TechnicalProfile, len(profiles))
	expects := make(map[string]bool)
	seen := make(map[[16]byte]bool, len(users))
	for _, p := range profiles {
		id, err := uuid.Parse(p.ProfileID)
		if err != nil || id == uuid.Nil {
			return elxjournal.ErrCorrupt
		}
		switch p.Phase {
		case "PREPARED":
			if denied[p.ProfileID] != 0 {
				return elxjournal.ErrCorrupt
			}
		case "INSTALLED":
			if denied[p.ProfileID] != 0 {
				return elxjournal.ErrCorrupt
			}
			if p.InboundTag == tag {
				if !isVLESS {
					return elxjournal.ErrUncertain
				}
				expects[p.ProfileID] = false
			}
		case "RETIRED":
			if p.RetireGeneration == 0 || denied[p.ProfileID] != p.RetireGeneration {
				return elxjournal.ErrCorrupt
			}
		default:
			return elxjournal.ErrUncertain
		}
		owners[vless.ProcessUUID(xrayuuid.UUID(id))] = p
	}
	if !isVLESS {
		return nil
	}
	for _, user := range users {
		if user == nil {
			return elxjournal.ErrUncertain
		}
		account, ok := user.Account.(*vless.MemoryAccount)
		if !ok || account == nil || account.ID == nil {
			return elxjournal.ErrUncertain
		}
		key := vless.ProcessUUID(account.ID.UUID())
		if seen[key] {
			return elxjournal.ErrCollision
		}
		seen[key] = true
		if p, reserved := owners[key]; reserved {
			if p.Phase != "INSTALLED" || p.InboundTag != tag ||
				user.Email != p.Email || uuid.UUID(account.ID.UUID()).String() != p.ProfileID ||
				account.Flow != p.Flow {
				return elxjournal.ErrCollision
			}
			expects[p.ProfileID] = true
			continue
		}
		for raw := range denied {
			id, err := uuid.Parse(raw)
			if err != nil || id == uuid.Nil {
				return elxjournal.ErrCorrupt
			}
			if vless.ProcessUUID(xrayuuid.UUID(id)) == key {
				return elxjournal.ErrCollision
			}
		}
	}
	for _, matched := range expects {
		if !matched {
			return elxjournal.ErrUncertain
		}
	}
	return nil
}

// WithTechnicalInboundRegistration serializes AddHandler (including Start)
// with every signed PREPARE, INSTALL and RETIRE. The ordering is always
// subscriptionMu before inbound.Manager.access, exactly like signed INSTALL.
// Holding the lock through the commit prevents stale preflight snapshots
// from being published by a racing hot reload.
func (m *Instance) WithTechnicalInboundRegistration(tag string, isVLESS bool,
	getUsers func() []*protocol.MemoryUser, commit func() error,
) error {
	if m == nil || commit == nil {
		return elxjournal.ErrInvalid
	}
	if !m.technicalProvisioning {
		return commit()
	}
	m.subscriptionMu.Lock()
	defer m.subscriptionMu.Unlock()
	if m.opJournal == nil || m.store == nil || m.store.failed ||
		m.opJournal.HasPending() {
		return elxjournal.ErrUncertain
	}
	profiles, err := m.opJournal.ListTechnicalProfiles()
	if err != nil {
		return err
	}
	var users []*protocol.MemoryUser
	if isVLESS {
		if getUsers == nil {
			return elxjournal.ErrUncertain
		}
		users = getUsers()
	}
	if err := validateTechnicalInboundRegistration(tag, isVLESS, users, profiles,
		m.opJournal.DeniedProfiles()); err != nil {
		return err
	}
	return commit()
}

// WithTechnicalInboundRemoval prevents a hot-reload from dropping the
// physical handler for any still-Control-owned PREPARED or INSTALLED profile.
// RETIRED profiles need no live handler. Core shutdown uses Manager.Close,
// not RemoveHandler, and cannot rewrite any durable authority.
func (m *Instance) WithTechnicalInboundRemoval(tag string, remove func() error) error {
	if m == nil || remove == nil {
		return elxjournal.ErrInvalid
	}
	if !m.technicalProvisioning {
		return remove()
	}
	m.subscriptionMu.Lock()
	defer m.subscriptionMu.Unlock()
	if m.opJournal == nil || m.store == nil || m.store.failed ||
		m.opJournal.HasPending() {
		return elxjournal.ErrUncertain
	}
	profiles, err := m.opJournal.ListTechnicalProfiles()
	if err != nil {
		return err
	}
	for _, p := range profiles {
		if p.InboundTag == tag && p.Phase != "RETIRED" {
			return elxjournal.ErrUncertain
		}
	}
	return remove()
}
