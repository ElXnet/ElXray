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
