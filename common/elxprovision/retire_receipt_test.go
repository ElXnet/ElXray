package elxprovision

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestRetiredCoreProofGoldenAndTampering(t *testing.T) {
	g, _ := testGrant(t)
	g.Version, g.Action, g.Flow = 2, Retire, "xtls-rprx-vision"
	h := sha256.Sum256(g.Transcript())
	if hex.EncodeToString(h[:]) != "07bb286a26be073e6fe63e002234f3846fb32eace4e4113b4079fd6c36b47908" {
		t.Fatal("Control/core RETIRE grant transcript mismatch")
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	proof := RetireReceipt{
		Version: 1, OperationID: g.OperationID, ProfileID: g.ProfileID,
		NodeID: g.NodeID, ExecutorID: g.ExecutorID, ResourceID: g.ResourceID,
		StoreID:             uuid.MustParse("66666666-6666-4666-8666-666666666666"),
		CoreIncarnation:     uuid.MustParse("77777777-7777-4777-8777-777777777777"),
		AuthorityGeneration: 9, PolicyRevision: 4, RetireGeneration: 2,
		TranscriptSHA256: hex.EncodeToString(h[:]),
	}
	sum := sha256.Sum256(proof.Transcript())
	if hex.EncodeToString(sum[:]) != "531a8623814add61ab52baec1dcab6910e3399fd246c352fe784c53775860c44" {
		t.Fatalf("Control/core RETIRED witness transcript diverged: %x", sum)
	}
	proof.Signature = ed25519.Sign(key, proof.Transcript())
	pub := key.Public().(ed25519.PublicKey)
	if err := VerifyRetireReceipt(proof, g, pub); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*RetireReceipt){
		func(p *RetireReceipt) { p.ProfileID = uuid.New() },
		func(p *RetireReceipt) { p.StoreID = uuid.New() },
		func(p *RetireReceipt) { p.RetireGeneration++ },
		func(p *RetireReceipt) { p.CoreIncarnation = uuid.New() },
	} {
		changed := proof
		changed.Signature = append([]byte(nil), proof.Signature...)
		mutate(&changed)
		if err := VerifyRetireReceipt(changed, g, pub); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("forged RETIRED proof accepted: %v", err)
		}
	}
}
