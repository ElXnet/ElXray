package inbound

import (
	"context"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	featureinbound "github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/proxy/vless"
)

// managedVLESSSnapshot reads the actual authentication validator rather
// than a caller-supplied JSON configuration or untrusted user email.
func managedVLESSSnapshot(ctx context.Context, handler featureinbound.Handler) ([]*protocol.MemoryUser, bool, error) {
	if handler == nil {
		return nil, false, errors.New("nil managed inbound handler")
	}
	source, ok := handler.(interface{ ElXVLESSTechnicalUsers() any })
	if !ok {
		return nil, false, nil
	}
	raw := source.ElXVLESSTechnicalUsers()
	if raw == nil {
		return nil, false, nil
	}
	users, ok := raw.(interface {
		GetUsers(context.Context) []*protocol.MemoryUser
	})
	if !ok {
		return nil, false, errors.New("uninspectable managed VLESS validator")
	}
	return users.GetUsers(ctx), true, nil
}

func managedVLESSKeys(users []*protocol.MemoryUser) (map[[16]byte]bool, error) {
	keys := make(map[[16]byte]bool, len(users))
	for _, user := range users {
		if user == nil {
			return nil, errors.New("nil managed VLESS user")
		}
		account, ok := user.Account.(*vless.MemoryAccount)
		if !ok || account == nil || account.ID == nil {
			return nil, errors.New("malformed managed VLESS authentication account")
		}
		key := vless.ProcessUUID(account.ID.UUID())
		if keys[key] {
			return nil, errors.New("duplicate effective managed VLESS UUID")
		}
		keys[key] = true
	}
	return keys, nil
}

// rejectManagedVLESSAliases MUST run only with inbound.Manager.access held,
// and, in technical managed mode, inside policy.subscriptionMu. It
// prohibits a new hot-reloaded validator from shadowing any active VLESS
// inbound even when neither identity belongs to a technical profile.
func (m *Manager) rejectManagedVLESSAliases(ctx context.Context, candidate featureinbound.Handler) error {
	incoming, isVLESS, err := managedVLESSSnapshot(ctx, candidate)
	if err != nil || !isVLESS {
		return err
	}
	ids, err := managedVLESSKeys(incoming)
	if err != nil {
		return err
	}
	check := func(handler featureinbound.Handler) error {
		users, vlessInbound, err := managedVLESSSnapshot(ctx, handler)
		if err != nil || !vlessInbound {
			return err
		}
		existing, err := managedVLESSKeys(users)
		if err != nil {
			return err
		}
		for id := range existing {
			if ids[id] {
				return errors.New("managed VLESS UUID collides across inbound handlers")
			}
		}
		return nil
	}
	for _, handler := range m.taggedHandlers {
		if err := check(handler); err != nil {
			return err
		}
	}
	for _, handler := range m.untaggedHandlers {
		if err := check(handler); err != nil {
			return err
		}
	}
	return nil
}
