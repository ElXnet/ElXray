package policy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/google/uuid"
)

func TestControlLeaseV3GoldenTranscriptAndBindingMutation(t *testing.T) {
	ids := [3]uuid.UUID{
		uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		uuid.MustParse("22222222-2222-4222-8222-222222222222"),
		uuid.MustParse("33333333-3333-4333-8333-333333333333"),
	}
	ticket := ControlLease{
		Version: 3, NodeID: ids[0], ResourceID: ids[1], ExecutorID: ids[2],
		Subscription: "entitlement-A", Sequence: 7, NotBefore: 1700000000,
		NotAfter: 1700000015, CeilingUp: 12500000, CeilingDown: 6250000,
		AuthorityGeneration: 9,
	}
	wire := ControlLeaseTranscript(ticket)
	got := sha256.Sum256(wire)
	if hex.EncodeToString(got[:]) != "ae629b1897c95b9faac7fb8204e18f58c90abdcfd6ff8dcc6bdd3b9c7fa177b7" {
		t.Fatalf("Control lease v3 transcript drift: %x", got)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, ed25519.SeedSize))
	sig := ed25519.Sign(key, wire)
	pub := key.Public().(ed25519.PublicKey)
	if !ed25519.Verify(pub, wire, sig) {
		t.Fatal("v3 lease signature invalid")
	}
	for _, change := range []func(*ControlLease){
		func(x *ControlLease) { x.Version = 2 },
		func(x *ControlLease) { x.NodeID = ids[1] },
		func(x *ControlLease) { x.ResourceID = ids[0] },
		func(x *ControlLease) { x.ExecutorID = ids[0] },
		func(x *ControlLease) { x.AuthorityGeneration++ },
		func(x *ControlLease) { x.Subscription += "-other" },
		func(x *ControlLease) { x.Sequence++ },
		func(x *ControlLease) { x.NotAfter++ },
		func(x *ControlLease) { x.CeilingUp++ },
		func(x *ControlLease) { x.CeilingDown++ },
	} {
		changed := ticket
		change(&changed)
		if ed25519.Verify(pub, ControlLeaseTranscript(changed), sig) {
			t.Fatalf("v3 signed lease accepted altered binding: %+v", changed)
		}
	}
}
