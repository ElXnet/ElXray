package policy

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common/elxjournal"
	"github.com/xtls/xray-core/common/subscriptionrate"
)

func TestRecoveredTechnicalIdentityNeverGrantsPayloadAndRestoresExactInstalledUser(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed durable journal requires Unix directory fsync")
	}
	storePath := filepath.Join(t.TempDir(), "journal.json")
	if err := elxjournal.Provision(storePath, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	journal, err := elxjournal.Open(storePath)
	if err != nil {
		t.Fatal(err)
	}
	node, resource, executor, profile, op := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	hash := sha256.Sum256([]byte("signed Control prepare"))
	p := elxjournal.TechnicalProfile{
		NodeID: node.String(), ResourceID: resource.String(),
		ExecutorID: executor.String(), ProfileID: profile.String(),
		OperationID: op.String(), SubscriptionID: "lab", Email: "device@lab",
		InboundTag: "vless-reality-01", ProfileGeneration: 1,
		AuthorityGeneration: 9, PolicyRevision: 1,
		NotAfterUnix:     time.Now().Add(time.Minute).Unix(),
		TranscriptSHA256: hex.EncodeToString(hash[:]), Phase: "PREPARED",
	}
	if err := journal.BootstrapResource(p.ResourceID, 1, 9); err != nil {
		t.Fatal(err)
	}
	if err := journal.RecordTechnicalPrepared(p); err != nil {
		t.Fatal(err)
	}
	manager := &Instance{
		technicalProvisioning: true,
		opJournal:             journal, store: &policyStore{},
		leaseNodeID: node,
		leaseBindings: map[string]leaseBinding{"lab": {
			ResourceID: resource, ExecutorID: executor, MinAuthorityGeneration: 9,
		}},
		subscriptionPolicies: map[string]subscriptionrate.Policy{
			"lab": {ID: "lab", Revision: 1, Disabled: false},
		},
	}
	profiles, err := manager.RecoveredTechnicalProfiles(p.InboundTag)
	if err != nil || len(profiles) != 0 {
		t.Fatalf("PREPARED created live VLESS user: %+v %v", profiles, err)
	}
	installOp := uuid.NewString()
	installHash := sha256.Sum256([]byte("separate signed Control install"))
	if _, err := journal.BeginTechnicalInstall(
		p.ProfileID, installOp, hex.EncodeToString(installHash[:]),
		"xtls-rprx-vision", 1, 9); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.RecoveredTechnicalProfiles(p.InboundTag); !errors.Is(err, elxjournal.ErrUncertain) {
		t.Fatalf("interrupted install rehydrated an unknown VLESS account: %v", err)
	}
	if _, err := journal.MarkTechnicalInstalled(p.ProfileID, installOp); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	manager.store.key = key
	if evidence, err := manager.recoveryTechnicalProfile(p.ProfileID, installOp, "INSTALLED"); err != nil || evidence.InstallOperationID != installOp {
		t.Fatalf("durable expired-op installed proof lookup failed: %+v %v", evidence, err)
	}
	if _, err := manager.recoveryTechnicalProfile(p.ProfileID, uuid.NewString(), "INSTALLED"); !errors.Is(err, elxjournal.ErrStale) {
		t.Fatalf("wrong historic INSTALL operation recovered: %v", err)
	}
	rehydrated, err := manager.RecoveredTechnicalProfiles(p.InboundTag)
	if err != nil || len(rehydrated) != 1 ||
		rehydrated[0].ProfileID != p.ProfileID ||
		rehydrated[0].Email != p.Email ||
		rehydrated[0].Flow != "xtls-rprx-vision" ||
		rehydrated[0].InstallOperationID != installOp {
		t.Fatalf("INSTALLED user not recovered exactly: %+v %v", rehydrated, err)
	}
	if manager.TechnicalVLESSPayloadAuthorized(profile) {
		t.Fatal("recovered technical profile bypassed independent owner proof")
	}
	foreign, err := manager.RecoveredTechnicalProfiles("another-vless-inbound")
	if err != nil || len(foreign) != 0 {
		t.Fatalf("recovery leaked VLESS user into another inbound: %+v %v", foreign, err)
	}
	retireOp := uuid.NewString()
	retireHash := sha256.Sum256([]byte("separate signed Control retire"))
	if _, err := journal.BeginTechnicalRetire(
		p.ProfileID, retireOp, hex.EncodeToString(retireHash[:]), 2, 1, 9); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.RecoveredTechnicalProfiles(p.InboundTag); !errors.Is(err, elxjournal.ErrUncertain) {
		t.Fatalf("interrupted retire reactivated a denied UUID: %v", err)
	}
	if _, err := journal.MarkTechnicalRetired(p.ProfileID, retireOp); err != nil {
		t.Fatal(err)
	}
	if evidence, err := manager.recoveryTechnicalProfile(p.ProfileID, retireOp, "RETIRED"); err != nil || evidence.RetireOperationID != retireOp {
		t.Fatalf("durable retired recovery lookup failed: %+v %v", evidence, err)
	}
	if _, err := manager.recoveryTechnicalProfile(p.ProfileID, installOp, "INSTALLED"); !errors.Is(err, elxjournal.ErrStale) {
		t.Fatalf("old installed proof was revived after RETIRE: %v", err)
	}
	done, err := manager.RecoveredTechnicalProfiles(p.InboundTag)
	if err != nil || len(done) != 0 {
		t.Fatalf("durably retired VLESS user reappeared: %+v %v", done, err)
	}
}
