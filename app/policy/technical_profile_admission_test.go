package policy

import (
	"testing"

	"github.com/google/uuid"
)

func TestStage4TechnicalProfilePreparationNeverAuthorizesPayload(t *testing.T) {
	pending := &Instance{technicalProvisioning: true}
	lab := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	if pending.TechnicalVLESSPayloadAuthorized(lab) {
		t.Fatal("prepared managed VLESS profile bypassed signed device admission")
	}
	if pending.TechnicalVLESSPayloadAuthorized(uuid.Nil) {
		t.Fatal("zero VLESS profile ID admitted")
	}
	legacy := &Instance{technicalProvisioning: false}
	if !legacy.TechnicalVLESSPayloadAuthorized(lab) {
		t.Fatal("Stage-2 or standalone VLESS compatibility was changed without opt-in")
	}
	if legacy.TechnicalVLESSPayloadAuthorized(uuid.Nil) {
		t.Fatal("nil/zero identity was accepted")
	}
}
