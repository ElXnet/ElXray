package elxprovision

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func testGrant(t *testing.T) (Grant, ed25519.PrivateKey) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	g := Grant{
		Version: 1, Action: Prepare,
		OperationID:    uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		NodeID:         uuid.MustParse("22222222-2222-4222-8222-222222222222"),
		ExecutorID:     uuid.MustParse("33333333-3333-4333-8333-333333333333"),
		ResourceID:     uuid.MustParse("44444444-4444-4444-8444-444444444444"),
		ProfileID:      uuid.MustParse("55555555-5555-4555-8555-555555555555"),
		SubscriptionID: "lab", Email: "device@lab", InboundTag: "vless-reality-01",
		ProfileGeneration: 2, AuthorityGeneration: 9, PolicyRevision: 4,
		NotBefore: 1700000000, NotAfter: 1700000030,
	}
	g.Signature = ed25519.Sign(key, g.Transcript())
	return g, key
}

func TestSignedProfilePreparationGoldenAndFailClosed(t *testing.T) {
	g, key := testGrant(t)
	digest := sha256.Sum256(g.Transcript())
	const golden = "8282465f046f0dea2b02289253ab1e29cf053742a4fb2a7e4697d3187b4ef1cd"
	if hex.EncodeToString(digest[:]) != golden {
		t.Fatalf("Control/core profile grant drift: %x", digest)
	}
	now := time.Unix(1700000008, 0)
	pinned := key.Public().(ed25519.PublicKey)
	reg, err := New(pinned, g.NodeID, g.ExecutorID, g.ResourceID)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Stage(g, now); err != nil {
		t.Fatal(err)
	}
	if err := reg.MarkInstalled(g.ProfileID, g.OperationID); err != nil {
		t.Fatal(err)
	}
	if reg.PayloadAuthorized(g.ProfileID) {
		t.Fatal("signed technical install admitted VPN payload before owner proof")
	}
	entry, ok := reg.Get(g.ProfileID)
	if !ok || entry.Phase != Installed {
		t.Fatal("verified install missing")
	}
	entry.Grant.Signature[0] ^= 1
	if err := reg.Stage(g, now); err != nil {
		t.Fatal("exact signed operation replay rejected")
	}
	if err := reg.MarkInstalled(g.ProfileID, uuid.New()); !errors.Is(err, ErrNotPrepared) {
		t.Fatal("unbound install ACK accepted")
	}
	// Operation ID reused for a different profile is a fatal conflict.
	reused := g
	reused.ProfileID = uuid.New()
	reused.Signature = ed25519.Sign(key, reused.Transcript())
	if err := reg.Stage(reused, now); !errors.Is(err, ErrCollision) {
		t.Fatalf("same ID with altered payload accepted: %v", err)
	}
	// A retired VLESS UUID can never be reintroduced, even at a later gen.
	retire := g
	retire.Action = Retire
	retire.OperationID = uuid.New()
	retire.ProfileGeneration = 3
	retire.Signature = ed25519.Sign(key, retire.Transcript())
	if err := reg.Stage(retire, now); err != nil {
		t.Fatal(err)
	}
	reintroduce := g
	reintroduce.OperationID = uuid.New()
	reintroduce.ProfileGeneration = 4
	reintroduce.Signature = ed25519.Sign(key, reintroduce.Transcript())
	if err := reg.Stage(reintroduce, now); !errors.Is(err, ErrStale) {
		t.Fatalf("retired profile reused: %v", err)
	}
	if reg.PayloadAuthorized(g.ProfileID) {
		t.Fatal("retired profile admitted payload")
	}
}

func TestSignedProfilePreparationRejectsCrossExecutorAndForgedFields(t *testing.T) {
	g, key := testGrant(t)
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = 7
	other := ed25519.NewKeyFromSeed(seed)
	now := time.Unix(1700000008, 0)
	pinned := key.Public().(ed25519.PublicKey)
	r, err := New(pinned, g.NodeID, g.ExecutorID, g.ResourceID)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Grant){
		func(x *Grant) { x.NodeID = uuid.New() },
		func(x *Grant) { x.ExecutorID = uuid.New() },
		func(x *Grant) { x.ResourceID = uuid.New() },
		func(x *Grant) { x.SubscriptionID = "other" },
		func(x *Grant) { x.InboundTag = "other" },
		func(x *Grant) { x.ProfileID = uuid.New() },
		func(x *Grant) { x.ProfileGeneration++ },
		func(x *Grant) { x.AuthorityGeneration++ },
		func(x *Grant) { x.PolicyRevision++ },
		func(x *Grant) { x.Signature[0] ^= 1 },
	} {
		changed := g
		changed.Signature = append([]byte(nil), g.Signature...)
		mutate(&changed)
		if err := r.Stage(changed, now); err == nil {
			t.Fatalf("signed tampering admitted: %+v", changed)
		}
	}
	badSigner := g
	badSigner.Signature = ed25519.Sign(other, g.Transcript())
	if err := r.Stage(badSigner, now); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong Control key accepted: %v", err)
	}
	if err := r.Stage(g, time.Unix(1700000040, 0)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expired signed grant accepted: %v", err)
	}
	malformed := g
	malformed.Email = "evil\nheader"
	malformed.Signature = ed25519.Sign(key, malformed.Transcript())
	if err := r.Stage(malformed, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("delimiter injection accepted: %v", err)
	}
}

func TestSignedGrantRegistryRejectsEffectiveVLESSUUIDAlias(t *testing.T) {
	original, privateKey := testGrant(t)
	registry, err := New(privateKey.Public().(ed25519.PublicKey),
		original.NodeID, original.ExecutorID, original.ResourceID)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1700000008, 0)
	if err := registry.Stage(original, now); err != nil {
		t.Fatal(err)
	}
	alias := original
	alias.OperationID = uuid.New()
	alias.ProfileID[6] ^= 1
	alias.ProfileID[7] ^= 2
	alias.Email = "different@lab"
	alias.InboundTag = "different-vless"
	alias.Signature = ed25519.Sign(privateKey, alias.Transcript())
	if err := registry.Stage(alias, now); !errors.Is(err, ErrCollision) {
		t.Fatalf("a distinct signed UUID alias hijacked the VLESS lookup key: %v", err)
	}
	if _, exists := registry.Get(alias.ProfileID); exists {
		t.Fatal("an aliased signed profile became registered")
	}
	if entry, exists := registry.Get(original.ProfileID); !exists || entry.Grant.Email != original.Email {
		t.Fatal("aliased signed profile replaced original")
	}
}
