package inbound

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common/protocol"
	xrayuuid "github.com/xtls/xray-core/common/uuid"
	featureinbound "github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/proxy/vless"
)

type stage4FakeVLESS struct {
	*stage4FakeHandler
	users []*protocol.MemoryUser
}

func (h *stage4FakeVLESS) ElXVLESSTechnicalUsers() any { return h }
func (h *stage4FakeVLESS) GetUsers(context.Context) []*protocol.MemoryUser { return h.users }

func staticManagedUser(id uuid.UUID, email string) *protocol.MemoryUser {
	return &protocol.MemoryUser{
		Email: email,
		Account: &vless.MemoryAccount{ID: protocol.NewID(xrayuuid.UUID(id))},
	}
}

func TestManagedHotReloadRejectsAliasesAcrossRunningVLESSInbounds(t *testing.T) {
	id := uuid.MustParse("12345678-1234-4abc-8def-123456789abc")
	aliasBytes := id
	aliasBytes[6] ^= 0x38
	aliasBytes[7] ^= 0x15
	alias := uuid.UUID(aliasBytes)
	manager := &Manager{
		taggedHandlers: map[string]featureinbound.Handler{
			"existing": &stage4FakeVLESS{
				stage4FakeHandler: &stage4FakeHandler{tag: "existing"},
				users: []*protocol.MemoryUser{staticManagedUser(id, "existing@lab")},
			},
		},
	}
	collision := &stage4FakeVLESS{
		stage4FakeHandler: &stage4FakeHandler{tag: "candidate"},
		users: []*protocol.MemoryUser{staticManagedUser(alias, "alias@lab")},
	}
	manager.access.Lock()
	err := manager.rejectManagedVLESSAliases(context.Background(), collision)
	manager.access.Unlock()
	if err == nil {
		t.Fatal("normalized static UUID alias crossed the running inbound boundary")
	}
	safe := &stage4FakeVLESS{
		stage4FakeHandler: &stage4FakeHandler{tag: "candidate"},
		users: []*protocol.MemoryUser{staticManagedUser(uuid.New(), "other@lab")},
	}
	manager.access.Lock()
	err = manager.rejectManagedVLESSAliases(context.Background(), safe)
	manager.access.Unlock()
	if err != nil {
		t.Fatal("independent VLESS inbound was rejected: ", err)
	}
}

func TestManagedHotReloadRefusesMalformedAndAliasedValidatorUsers(t *testing.T) {
	id := uuid.MustParse("12345678-1234-4abc-8def-123456789abc")
	alias := id
	alias[6] ^= 0x55
	for _, users := range [][]*protocol.MemoryUser{
		{nil},
		{{Email: "malformed"}},
		{staticManagedUser(id, "one"), staticManagedUser(alias, "two")},
	} {
		if _, err := managedVLESSKeys(users); err == nil {
			t.Fatal("malformed or duplicate effective VLESS validator was accepted")
		}
	}
}
