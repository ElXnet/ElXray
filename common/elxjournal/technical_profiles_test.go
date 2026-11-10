package elxjournal

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"runtime"
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
	if runtime.GOOS == "windows" {
		t.Skip("managed durable journal requires Unix directory fsync; Windows must fail closed")
	}
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
	if runtime.GOOS == "windows" {
		t.Skip("managed durable journal requires Unix directory fsync; Windows must fail closed")
	}
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

func TestTechnicalProfileRejectsVLESSNormalizedUUIDAlias(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("durable managed journal needs Unix directory fsync; Windows remains fail-closed")
	}
	path := filepath.Join(t.TempDir(), "managed-v2.json")
	if err := Provision(path, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	j, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	p := technicalFixture()
	if err := j.BootstrapResource(p.ResourceID, 1, p.AuthorityGeneration); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordTechnicalPrepared(p); err != nil {
		t.Fatal(err)
	}
	aliasID := uuid.MustParse(p.ProfileID)
	aliasID[6] ^= 1
	aliasID[7] ^= 2
	alias := p
	alias.ProfileID = aliasID.String()
	alias.OperationID = uuid.NewString()
	alias.Email = "different@lab"
	if vlessLookupKey(alias.ProfileID) != vlessLookupKey(p.ProfileID) {
		t.Fatal("test fixture must share the effective VLESS lookup key")
	}
	if err := j.RecordTechnicalPrepared(alias); !errors.Is(err, ErrCollision) {
		t.Fatalf("effective VLESS UUID alias was durably reserved: %v", err)
	}
	if _, err := Open(path); err != nil {
		t.Fatalf("rejected alias corrupted the journal: %v", err)
	}

	// A permanent denial also applies to every alias of its effective UUID.
	denyPath := filepath.Join(t.TempDir(), "denied-v2.json")
	if err := Provision(denyPath, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	denials, err := Open(denyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := denials.BootstrapResource(p.ResourceID, 1, p.AuthorityGeneration); err != nil {
		t.Fatal(err)
	}
	if err := denials.RecordDeniedProfile(p.ProfileID, 1); err != nil {
		t.Fatal(err)
	}
	if err := denials.RecordTechnicalPrepared(alias); !errors.Is(err, ErrStale) {
		t.Fatalf("alias of permanently denied VLESS UUID was restored: %v", err)
	}
	if err := denials.RecordDeniedProfile(alias.ProfileID, 2); !errors.Is(err, ErrCollision) {
		t.Fatalf("duplicate tombstone key undermines future restore validation: %v", err)
	}
}

func TestTechnicalInstallIntentCrashReplayAndCompletion(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed durable journal requires Unix directory fsync")
	}
	path := filepath.Join(t.TempDir(), "managed.json")
	if err := Provision(path, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	j, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	p := technicalFixture()
	if err := j.BootstrapResource(p.ResourceID, p.PolicyRevision, p.AuthorityGeneration); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordTechnicalPrepared(p); err != nil {
		t.Fatal(err)
	}
	op := uuid.NewString()
	h := sha256.Sum256([]byte("signed-v2-install-transcript"))
	digest := hex.EncodeToString(h[:])
	if _, err := j.BeginTechnicalInstall(p.ProfileID, op, digest, "xtls-rprx-vision", p.PolicyRevision, p.AuthorityGeneration); err != nil {
		t.Fatal(err)
	}
	if !j.HasPending() {
		t.Fatal("interrupted VLESS install was not marked uncertain")
	}
	restored, err := Open(path)
	if err != nil || !restored.HasPending() {
		t.Fatalf("reboot lost pending live install fence: %v", err)
	}
	if _, err := restored.BeginTechnicalInstall(p.ProfileID, op, digest, "xtls-rprx-vision", p.PolicyRevision, p.AuthorityGeneration); !errors.Is(err, ErrUncertain) {
		t.Fatalf("uncertain install retried without live readback: %v", err)
	}
	if _, err := restored.MarkTechnicalInstalled(p.ProfileID, uuid.NewString()); !errors.Is(err, ErrStale) {
		t.Fatalf("wrong install operation produced INSTALLED: %v", err)
	}
	// Production code only calls Mark after live VLESS GetUser succeeds.
	done, err := restored.MarkTechnicalInstalled(p.ProfileID, op)
	if err != nil || done.Phase != "INSTALLED" || done.Flow != "xtls-rprx-vision" {
		t.Fatalf("live-verified install did not persist: %+v %v", done, err)
	}
	reopened, err := Open(path)
	if err != nil || reopened.HasPending() {
		t.Fatalf("verified install remained an unknown mutation: %v", err)
	}
	if saved, ok := reopened.TechnicalProfile(p.ProfileID); !ok || saved != done {
		t.Fatalf("installed technical identity not restored: %+v %v", saved, ok)
	}
	if _, err := reopened.BeginTechnicalInstall(p.ProfileID, uuid.NewString(), digest, "xtls-rprx-vision", p.PolicyRevision, p.AuthorityGeneration); !errors.Is(err, ErrCollision) {
		t.Fatalf("new operation reused installed identity: %v", err)
	}
}

func TestTechnicalRetirePersistsTombstoneBeforeLiveRemovalAndSurvivesRestart(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed durable journal requires Unix directory fsync")
	}
	path := filepath.Join(t.TempDir(), "managed.json")
	if err := Provision(path, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	j, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	p := technicalFixture()
	if err := j.BootstrapResource(p.ResourceID, p.PolicyRevision, p.AuthorityGeneration); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordTechnicalPrepared(p); err != nil {
		t.Fatal(err)
	}
	installOp := uuid.NewString()
	h := sha256.Sum256([]byte("v2-install"))
	if _, err := j.BeginTechnicalInstall(p.ProfileID, installOp, hex.EncodeToString(h[:]), "", p.PolicyRevision, p.AuthorityGeneration); err != nil {
		t.Fatal(err)
	}
	if _, err := j.MarkTechnicalInstalled(p.ProfileID, installOp); err != nil {
		t.Fatal(err)
	}
	retireOp := uuid.NewString()
	sum := sha256.Sum256([]byte("signed-retire-transcript"))
	digest := hex.EncodeToString(sum[:])
	before, err := j.BeginTechnicalRetire(p.ProfileID, retireOp, digest, 2, p.PolicyRevision, p.AuthorityGeneration)
	if err != nil || before.Phase != "RETIRING" || !j.HasPending() {
		t.Fatalf("failed to persist fail-closed retire intent: %+v %v", before, err)
	}
	if j.DeniedProfiles()[p.ProfileID] != 2 {
		t.Fatal("retire mutation left UUID without permanent denial")
	}
	reopened, err := Open(path)
	if err != nil || !reopened.HasPending() {
		t.Fatalf("crashed retire failed to restore in uncertain state: %v", err)
	}
	if _, err := reopened.BeginTechnicalRetire(p.ProfileID, retireOp, digest, 2, p.PolicyRevision, p.AuthorityGeneration); !errors.Is(err, ErrUncertain) {
		t.Fatalf("interrupted retire replay was allowed: %v", err)
	}
	if _, err := reopened.MarkTechnicalRetired(p.ProfileID, uuid.NewString()); !errors.Is(err, ErrStale) {
		t.Fatalf("wrong operation retired a profile: %v", err)
	}
	done, err := reopened.MarkTechnicalRetired(p.ProfileID, retireOp)
	if err != nil || done.Phase != "RETIRED" || reopened.HasPending() {
		t.Fatalf("verified VLESS absence did not finish durable retire: %+v %v", done, err)
	}
	final, err := Open(path)
	if err != nil || final.HasPending() {
		t.Fatalf("tombstone+retired profile could not be restored: %v", err)
	}
	if stored, ok := final.TechnicalProfile(p.ProfileID); !ok || stored != done {
		t.Fatalf("retired profile not durable: %+v %v", stored, ok)
	}
	if _, err := final.BeginTechnicalRetire(p.ProfileID, retireOp, digest, 2, p.PolicyRevision, p.AuthorityGeneration); err != nil {
		t.Fatalf("identical signed retire replay failed idempotency: %v", err)
	}
	if err := final.RecordTechnicalPrepared(p); !errors.Is(err, ErrStale) {
		t.Fatalf("retired UUID was resurrected: %v", err)
	}
	alias := p
	alias.ProfileID = uuid.MustParse(p.ProfileID).String()
	id := uuid.MustParse(alias.ProfileID)
	id[6] ^= 1
	alias.ProfileID = id.String()
	alias.OperationID = uuid.NewString()
	alias.Email = "alias@lab"
	if err := final.RecordTechnicalPrepared(alias); !errors.Is(err, ErrStale) {
		t.Fatalf("retired effective UUID alias reissued: %v", err)
	}
}
