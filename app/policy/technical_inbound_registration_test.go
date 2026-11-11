package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common/elxjournal"
	"github.com/xtls/xray-core/common/protocol"
)

func managedInboundLab(t *testing.T) (*Instance, elxjournal.TechnicalProfile) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("managed durable journal requires Unix directory fsync")
	}
	path := filepath.Join(t.TempDir(), "journal.json")
	if err := elxjournal.Provision(path, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	journal, err := elxjournal.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	node, resource, executor, profile, operation := uuid.NewString(),
		uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	digest := sha256.Sum256([]byte("signed Control technical PREPARE"))
	p := elxjournal.TechnicalProfile{
		ProfileID: profile, OperationID: operation,
		NodeID: node, ResourceID: resource, ExecutorID: executor,
		SubscriptionID: "lab", Email: "device@lab", InboundTag: "vless-primary",
		ProfileGeneration: 1, AuthorityGeneration: 9, PolicyRevision: 1,
		NotAfterUnix: time.Now().Add(time.Hour).Unix(),
		TranscriptSHA256: hex.EncodeToString(digest[:]), Phase: "PREPARED",
	}
	if err := journal.BootstrapResource(resource, 1, 9); err != nil {
		t.Fatal(err)
	}
	if err := journal.RecordTechnicalPrepared(p); err != nil {
		t.Fatal(err)
	}
	return &Instance{technicalProvisioning: true, opJournal: journal, store: &policyStore{}}, p
}

func managedInstalledLab(t *testing.T) (*Instance, elxjournal.TechnicalProfile) {
	t.Helper()
	m, p := managedInboundLab(t)
	op := uuid.NewString()
	digest := sha256.Sum256([]byte("separate signed Control INSTALL"))
	if _, err := m.opJournal.BeginTechnicalInstall(p.ProfileID, op,
		hex.EncodeToString(digest[:]), "", 1, 9); err != nil {
		t.Fatal(err)
	}
	installed, err := m.opJournal.MarkTechnicalInstalled(p.ProfileID, op)
	if err != nil {
		t.Fatal(err)
	}
	return m, installed
}

func TestManagedInboundRegistrationRechecksDurableUUIDInsideCommitLock(t *testing.T) {
	manager, p := managedInboundLab(t)
	id := uuid.MustParse(p.ProfileID)
	aliasBytes := id
	aliasBytes[6] ^= 0x49
	aliasBytes[7] ^= 0x72
	alias := uuid.UUID(aliasBytes)
	runs := 0
	register := func() error { runs++; return nil }
	for _, candidate := range []uuid.UUID{id, alias} {
		err := manager.WithTechnicalInboundRegistration("vless-shadow", true,
			func() []*protocol.MemoryUser {
				return []*protocol.MemoryUser{scopeUser(candidate, "shadow@lab")}
			}, register)
		if !errors.Is(err, elxjournal.ErrCollision) {
			t.Fatalf("shadow VLESS UUID %s passed managed registration: %v", candidate, err)
		}
	}
	if runs != 0 {
		t.Fatal("rejected inbound was published despite a durable UUID collision")
	}
	safe := uuid.New()
	err := manager.WithTechnicalInboundRegistration("vless-shadow", true,
		func() []*protocol.MemoryUser {
			return []*protocol.MemoryUser{scopeUser(safe, "unrelated@lab")}
		}, register)
	if err != nil || runs != 1 {
		t.Fatalf("unrelated inbound registration failed: %v; callbacks %d", err, runs)
	}
	if err := manager.WithTechnicalInboundRemoval("vless-primary", register);
		!errors.Is(err, elxjournal.ErrUncertain) {
		t.Fatalf("PREPARED technical inbound was removed before Control authority ended: %v", err)
	}
}

func TestManagedInstalledInboundMustMatchExactTagAndAccount(t *testing.T) {
	manager, p := managedInstalledLab(t)
	id := uuid.MustParse(p.ProfileID)
	count := 0
	register := func() error { count++; return nil }
	valid := func() []*protocol.MemoryUser {
		return []*protocol.MemoryUser{scopeUser(id, p.Email)}
	}
	if err := manager.WithTechnicalInboundRegistration(p.InboundTag, true,
		valid, register); err != nil {
		t.Fatalf("exact journal-rehydrated technical VLESS user rejected: %v", err)
	}
	if count != 1 {
		t.Fatal("legitimate recovered inbound was not published exactly once")
	}
	cases := []struct {
		name string
		tag string
		isVLESS bool
		users []*protocol.MemoryUser
	}{
		{"wrong tag", "vless-shadow", true, valid()},
		{"wrong email", p.InboundTag, true,
			[]*protocol.MemoryUser{scopeUser(id, "shadow@lab")}},
		{"missing installed user", p.InboundTag, true, nil},
		{"replace with non-VLESS", p.InboundTag, false, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := manager.WithTechnicalInboundRegistration(tc.tag, tc.isVLESS,
				func() []*protocol.MemoryUser { return tc.users }, register)
			if err == nil {
				t.Fatal("a missing or shadowed installed technical user was published")
			}
		})
	}
	if count != 1 {
		t.Fatal("invalid inbound registration executed its commit callback")
	}
	if err := manager.WithTechnicalInboundRemoval(p.InboundTag, register);
		!errors.Is(err, elxjournal.ErrUncertain) {
		t.Fatalf("hot reload removed a Control-owned installed profile: %v", err)
	}
	if count != 1 {
		t.Fatal("installed technical inbound removal executed its callback")
	}
}

func TestManagedInboundRegistrationCannotRaceSignedProfileMutation(t *testing.T) {
	manager, p := managedInboundLab(t)
	id := uuid.MustParse(p.ProfileID)
	// The first goroutine already owns the signing/mutation lock.
	// A second inbound reload must not enter its commit callback until
	// the first mutation has finished and the journal is rechecked.
	manager.subscriptionMu.Lock()
	done := make(chan error, 1)
	committed := make(chan struct{}, 1)
	go func() {
		done <- manager.WithTechnicalInboundRegistration("other-inbound", true,
			func() []*protocol.MemoryUser {
				return []*protocol.MemoryUser{scopeUser(id, "shadow@lab")}
			}, func() error {
				committed <- struct{}{}
				return nil
			})
	}()
	select {
	case <-committed:
		manager.subscriptionMu.Unlock()
		t.Fatal("inbound was registered while signed mutation lock was held")
	case <-time.After(20 * time.Millisecond):
	}
	manager.subscriptionMu.Unlock()
	select {
	case err := <-done:
		if !errors.Is(err, elxjournal.ErrCollision) {
			t.Fatalf("racing reconfiguration bypassed persisted PREPARE: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("concurrent managed inbound guard deadlocked")
	}
	select {
	case <-committed:
		t.Fatal("racing inbound committed despite durable signed UUID reservation")
	default:
	}
}

func TestStandaloneInboundChangeKeepsLegacyBehavior(t *testing.T) {
	legacy := &Instance{technicalProvisioning: false}
	count := 0
	call := func() error { count++; return nil }
	if err := legacy.WithTechnicalInboundRegistration("legacy", false, nil, call); err != nil {
		t.Fatal(err)
	}
	if err := legacy.WithTechnicalInboundRemoval("legacy", call); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("standalone inbound changes were blocked: %d", count)
	}
}
