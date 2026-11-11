package policy

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common/elxjournal"
	"github.com/xtls/xray-core/common/protocol"
	xrayuuid "github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/vless"
)

func scopeUser(id uuid.UUID, email string) *protocol.MemoryUser {
	return &protocol.MemoryUser{
		Email: email,
		Account: &vless.MemoryAccount{
			ID: protocol.NewID(xrayuuid.UUID(id)),
		},
	}
}

func TestTechnicalVLESSScopeAcrossInbounds(t *testing.T) {
	id := uuid.MustParse("12345678-1234-4abc-8def-123456789abc")
	// VLESS ignores UUID bytes 6/7: its lookup sees the same identity.
	alias := uuid.MustParse("12345678-1234-0000-8def-123456789abc")
	other := uuid.MustParse("12345678-1234-4abc-8def-123456789abd")
	tests := []struct {
		name      string
		inbounds  []technicalInboundSnapshot
		installed bool
		want      error
	}{
		{"clean prepare", []technicalInboundSnapshot{{tag: "primary"}, {tag: "backup"}}, false, nil},
		{"own installed", []technicalInboundSnapshot{
			{tag: "primary", users: []*protocol.MemoryUser{scopeUser(id, "device@lab")}},
			{tag: "backup"},
		}, true, nil},
		{"alias in foreign inbound", []technicalInboundSnapshot{
			{tag: "primary"}, {tag: "backup", users: []*protocol.MemoryUser{scopeUser(alias, "shadow@lab")}},
		}, false, elxjournal.ErrCollision},
		{"alias despite exact installed", []technicalInboundSnapshot{
			{tag: "primary", users: []*protocol.MemoryUser{scopeUser(id, "device@lab")}},
			{tag: "backup", users: []*protocol.MemoryUser{scopeUser(alias, "shadow@lab")}},
		}, true, elxjournal.ErrCollision},
		{"same UUID in foreign inbound", []technicalInboundSnapshot{
			{tag: "primary"}, {tag: "backup", users: []*protocol.MemoryUser{scopeUser(id, "shadow@lab")}},
		}, false, elxjournal.ErrCollision},
		{"own email collision", []technicalInboundSnapshot{
			{tag: "primary", users: []*protocol.MemoryUser{scopeUser(other, "device@lab")}},
		}, false, elxjournal.ErrCollision},
		{"wrong own email", []technicalInboundSnapshot{
			{tag: "primary", users: []*protocol.MemoryUser{scopeUser(id, "shadow@lab")}},
		}, true, elxjournal.ErrCollision},
		{"unknown target", []technicalInboundSnapshot{{tag: "backup"}}, false, elxjournal.ErrUncertain},
		{"duplicate target tags", []technicalInboundSnapshot{{tag: "primary"}, {tag: "primary"}}, false, elxjournal.ErrUncertain},
		{"malformed validator", []technicalInboundSnapshot{
			{tag: "primary", users: []*protocol.MemoryUser{{Email: "x"}}},
		}, false, elxjournal.ErrUncertain},
		{"missing installed UUID", []technicalInboundSnapshot{{tag: "primary"}}, true, elxjournal.ErrUncertain},
		{"retired UUID is still live", []technicalInboundSnapshot{
			{tag: "primary"}, {tag: "backup", users: []*protocol.MemoryUser{scopeUser(alias, "old@lab")}},
		}, false, elxjournal.ErrCollision},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateTechnicalVLESSScope(tc.inbounds, "primary", "device@lab", id, tc.installed)
			if !errors.Is(err, tc.want) {
				t.Fatalf("scope check = %v; want %v", err, tc.want)
			}
		})
	}
}
