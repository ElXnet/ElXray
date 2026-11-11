package policy

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common/elxjournal"
	"github.com/xtls/xray-core/common/protocol"
)

func TestTechnicalVLESSBootstrapRejectsStaticAliasesAcrossInbounds(t *testing.T) {
	id := uuid.MustParse("12345678-1234-4abc-8def-123456789abc")
	alias := uuid.MustParse("12345678-1234-0000-8def-123456789abc")
	unrelated := uuid.MustParse("12345678-1234-4abc-8def-123456789abd")

	for _, phase := range []string{"PREPARED", "INSTALLED", "RETIRED"} {
		t.Run(phase, func(t *testing.T) {
			journal := []elxjournal.TechnicalProfile{
				{ProfileID: id.String(), InboundTag: "node-a", Phase: phase},
			}
			// The test simulates constructing a DIFFERENT inbound that has
			// a static account whose VLESS authentication UUID aliases the
			// durable technical identity on node-a.
			for _, rejected := range []uuid.UUID{id, alias} {
				err := validateTechnicalVLESSBootstrap(
					[]*protocol.MemoryUser{scopeUser(rejected, "static-other@lab")},
					journal, nil)
				if !errors.Is(err, elxjournal.ErrCollision) {
					t.Fatalf("%s static UUID %s accepted: %v", phase, rejected, err)
				}
			}
			if err := validateTechnicalVLESSBootstrap(
				[]*protocol.MemoryUser{scopeUser(unrelated, "static-safe@lab")},
				journal, nil); err != nil {
				t.Fatalf("unrelated static VLESS user rejected: %v", err)
			}
		})
	}
}

func TestTechnicalVLESSBootstrapChecksTombstonesAndMalformedAccounts(t *testing.T) {
	id := uuid.MustParse("12345678-1234-4abc-8def-123456789abc")
	alias := uuid.MustParse("12345678-1234-0000-8def-123456789abc")
	tombstone := map[string]uint64{id.String(): 2}
	if err := validateTechnicalVLESSBootstrap(
		[]*protocol.MemoryUser{scopeUser(alias, "static@lab")},
		nil, tombstone); !errors.Is(err, elxjournal.ErrCollision) {
		t.Fatalf("retired UUID alias bypassed durable tombstone: %v", err)
	}
	for _, users := range [][]*protocol.MemoryUser{
		{nil},
		{{Email: "missing-vless-account"}},
	} {
		if err := validateTechnicalVLESSBootstrap(users, nil, nil); !errors.Is(err, elxjournal.ErrUncertain) {
			t.Fatalf("invalid user configuration failed open: %v", err)
		}
	}
	if err := validateTechnicalVLESSBootstrap(nil, nil,
		map[string]uint64{id.String(): 0}); !errors.Is(err, elxjournal.ErrCorrupt) {
		t.Fatalf("invalid durable denial generation accepted: %v", err)
	}
	if err := validateTechnicalVLESSBootstrap(nil,
		[]elxjournal.TechnicalProfile{{ProfileID: id.String()}, {ProfileID: alias.String()}},
		nil); !errors.Is(err, elxjournal.ErrCollision) {
		t.Fatalf("colliding technical journal entries accepted: %v", err)
	}
	if err := validateTechnicalVLESSBootstrap(nil, nil,
		map[string]uint64{id.String(): 2, alias.String(): 3}); !errors.Is(err, elxjournal.ErrCollision) {
		t.Fatalf("aliased permanent tombstones accepted: %v", err)
	}
	if err := validateTechnicalVLESSBootstrap(nil,
		[]elxjournal.TechnicalProfile{{ProfileID: id.String()}},
		map[string]uint64{id.String(): 2}); err != nil {
		t.Fatalf("the same retired technical UUID and tombstone should coexist: %v", err)
	}
	if err := validateTechnicalVLESSBootstrap(nil, nil, nil); err != nil {
		t.Fatalf("clean technical bootstrap refused: %v", err)
	}
}

func TestTechnicalVLESSBootstrapRetainsStandaloneBehavior(t *testing.T) {
	id := uuid.MustParse("12345678-1234-4abc-8def-123456789abc")
	legacy := &Instance{technicalProvisioning: false}
	if err := legacy.ValidateTechnicalVLESSBootstrap(
		[]*protocol.MemoryUser{scopeUser(id, "legacy@lab")}); err != nil {
		t.Fatalf("standalone mode was changed by Stage-4 protection: %v", err)
	}
	if err := (&Instance{technicalProvisioning: true}).ValidateTechnicalVLESSBootstrap(nil); !errors.Is(err, elxjournal.ErrUncertain) {
		t.Fatalf("technical mode with no durable journal failed open: %v", err)
	}
}
