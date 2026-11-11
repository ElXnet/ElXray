package policy

import (
	"github.com/google/uuid"
	"github.com/xtls/xray-core/common/elxjournal"
	"github.com/xtls/xray-core/common/protocol"
	xrayuuid "github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	inboundfeature "github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/proxy/vless"
)

// technicalInboundSnapshot describes a distinct running VLESS validator.
// Comparing only inbound tags or configured JSON IDs would miss the
// VLESS-normalized authentication key, where UUID bytes 6 and 7 are ignored.
type technicalInboundSnapshot struct {
	tag   string
	users []*protocol.MemoryUser
}

// validateTechnicalVLESSScope rejects an effective UUID collision across
// ALL VLESS inbounds, including unrelated static users. The ownInstalled
// exception applies only to the exact target inbound, email AND original
// unnormalized UUID. Shadow aliases cannot borrow the exception.
func validateTechnicalVLESSScope(inbounds []technicalInboundSnapshot,
	targetTag, email string, profile uuid.UUID, ownInstalled bool,
) error {
	if targetTag == "" || email == "" || profile == uuid.Nil {
		return elxjournal.ErrInvalid
	}
	normalized := vless.ProcessUUID(xrayuuid.UUID(profile))
	targets, owned := 0, 0
	for _, inbound := range inbounds {
		if inbound.tag == targetTag {
			targets++
		}
		for _, user := range inbound.users {
			if user == nil {
				return elxjournal.ErrUncertain
			}
			account, ok := user.Account.(*vless.MemoryAccount)
			if !ok || account == nil || account.ID == nil {
				return elxjournal.ErrUncertain
			}
			if vless.ProcessUUID(account.ID.UUID()) == normalized {
				if ownInstalled && inbound.tag == targetTag &&
					user.Email == email && uuid.UUID(account.ID.UUID()) == profile {
					owned++
					continue
				}
				return elxjournal.ErrCollision
			}
			if inbound.tag == targetTag && user.Email == email {
				return elxjournal.ErrCollision
			}
		}
	}
	if targets != 1 || (ownInstalled && owned != 1) {
		return elxjournal.ErrUncertain
	}
	return nil
}

// verifyTechnicalVLESSScope takes a new snapshot of every running inbound.
// The caller holds subscriptionMu, serializing all signed technical changes.
// Generic HandlerService mutations are forbidden in managed mode; a future
// reload must also preserve the global UUID admission fence.
func (m *Instance) verifyTechnicalVLESSScope(tag, email string, profile uuid.UUID, ownInstalled bool) error {
	if m == nil || m.runtimeContext == nil {
		return elxjournal.ErrUncertain
	}
	runtime := core.FromContext(m.runtimeContext)
	if runtime == nil {
		return elxjournal.ErrUncertain
	}
	manager, ok := runtime.GetFeature(inboundfeature.ManagerType()).(inboundfeature.Manager)
	if !ok {
		return elxjournal.ErrUncertain
	}
	live := manager.ListHandlers(m.runtimeContext)
	inbounds := make([]technicalInboundSnapshot, 0, len(live))
	for _, handler := range live {
		if handler == nil {
			return elxjournal.ErrUncertain
		}
		source, isVLESS := handler.(interface{ ElXVLESSTechnicalUsers() any })
		if !isVLESS {
			if handler.Tag() == tag {
				return elxjournal.ErrUncertain
			}
			continue
		}
		users, ok := source.ElXVLESSTechnicalUsers().(technicalVLESSUserManager)
		if !ok || users == nil {
			return elxjournal.ErrUncertain
		}
		inbounds = append(inbounds, technicalInboundSnapshot{
			tag: handler.Tag(), users: users.GetUsers(m.runtimeContext),
		})
	}
	return validateTechnicalVLESSScope(inbounds, tag, email, profile, ownInstalled)
}
