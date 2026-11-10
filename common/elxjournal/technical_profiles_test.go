package elxjournal

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
)

func technicalFixture() TechnicalProfile {
	digest := sha256.Sum256([]byte("independent-control-grant-fixture"))
	return TechnicalProfile{
		ProfileID: uuid.NewString(), OperationID: uuid.NewString(),
		NodeID: uuid.NewString(), ResourceID: uuid.NewString(),
		ExecutorID: uuid.NewString(), SubscriptionID: "lab",
		Email: "user@lab", InboundTag: "vless-reality-01",
		ProfileGeneration: 1, AuthorityGeneration: 9,
		PolicyRevision: 1, NotAfterUnix: time.Now().Add(time.Minute).Unix(),
		TranscriptSHA256: hex.EncodeToString(digest[:]), Phase: "PREPARED",
	}
}

func TestTechnicalProfileDurablePreparationCannotBecomeAdmission(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed-v2.json")
	if err := Provision(path, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	j, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	p := technicalFixture()
	if err := j.BootstrapResource(p.ResourceID, 1, 9); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordTechnicalPrepared(p); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordTechnicalPrepared(p); err != nil {
		t.Fatalf("same signed operation should be idempotent: %v", err)
	}
	restored, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	recorded, ok := restored.TechnicalProfile(p.ProfileID)
	if !ok || recorded != p || recorded.Phase != "PREPARED" {
		t.Fatalf("prepared identity was not durably restored: %+v %v", recorded, ok)
	}
	if restored.HasPending() {
		t.Fatal("technical preparation must not be misreported as a live applied operation")
	}
	changed := p
	changed.TranscriptSHA256 = hex.EncodeToString(make([]byte, sha256.Size))
	if err := restored.RecordTechnicalPrepared(changed); !errors.Is(err, ErrCollision) {
		t.Fatalf("changed signed intent reused same VLESS UUID: %v", err)
	}
	changed = p
	changed.ProfileID = uuid.NewString()
	if err := restored.RecordTechnicalPrepared(changed); !errors.Is(err, ErrCollision) {
		t.Fatalf("same operation ID reused for foreign VLESS UUID: %v", err)
	}
	changed = p
	changed.ProfileID, changed.OperationID = uuid.NewString(), uuid.NewString()
	if err := restored.RecordTechnicalPrepared(changed); !errors.Is(err, ErrCollision) {
		t.Fatalf("same inbound email assigned twice: %v", err)
	}
	changed = p
	changed.ProfileID, changed.OperationID = uuid.NewString(), uuid.NewString()
	changed.Email = "other@lab"
	changed.AuthorityGeneration = 8
	if err := restored.RecordTechnicalPrepared(changed); !errors.Is(err, ErrStale) {
		t.Fatalf("old authority generation prepared a profile: %v", err)
	}
	changed.AuthorityGeneration = 9
	changed.PolicyRevision = 2
	if err := restored.RecordTechnicalPrepared(changed); !errors.Is(err, ErrStale) {
		t.Fatalf("future unknown policy revision prepared a profile: %v", err)
	}
}

func TestTechnicalProfileCannotReuseDurableDeniedUUID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed-v2.json")
	if err := Provision(path, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	j, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	p := technicalFixture()
	if err := j.BootstrapResource(p.ResourceID, 1, 9); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordDeniedProfile(p.ProfileID, 1); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordTechnicalPrepared(p); !errors.Is(err, ErrStale) {
		t.Fatalf("tombstoned technical UUID was revived: %v", err)
	}
	if reopened, err := Open(path); err != nil || reopened == nil {
		t.Fatalf("failed to read old stage3-format v2 snapshot: %v", err)
	}
}
