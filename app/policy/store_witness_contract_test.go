package policy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestCoreStoreWitnessGoldenMatchesControl(t *testing.T) {
	w := SignedStoreWitness{
		Version:             2,
		NodeID:              "22222222-2222-4222-8222-222222222222",
		ResourceID:          "33333333-3333-4333-8333-333333333333",
		ExecutorID:          "44444444-4444-4444-8444-444444444444",
		StoreID:             "66666666-6666-4666-8666-666666666666",
		AuthorityGeneration: 9, CoreRevision: 2,
		CoreIncarnation:  "55555555-5555-4555-8555-555555555555",
		LastOperationID:  "11111111-1111-4111-8111-111111111111",
		TombstonesSHA256: "eab4b2179450179f4800ff300bcc16116728c6dd60bf5ea2e10020b9ef0f5693",
		Nonce:            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		NotBefore:        1700000000, NotAfter: 1700000015,
	}
	sum := sha256.Sum256(StoreWitnessTranscript(w))
	if hex.EncodeToString(sum[:]) != "0a4db3a3f4127c05fce5a9db65ece76326fafadc9025f3f5b3167c74609258db" {
		t.Fatalf("ElXray/ElX-control independent witness drift: %x", sum)
	}
	k := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	sig := ed25519.Sign(k, StoreWitnessTranscript(w))
	for _, m := range []func(*SignedStoreWitness){
		func(x *SignedStoreWitness) { x.NodeID = x.ResourceID },
		func(x *SignedStoreWitness) { x.ResourceID = x.NodeID },
		func(x *SignedStoreWitness) { x.ExecutorID = x.StoreID },
		func(x *SignedStoreWitness) { x.StoreID = x.ExecutorID },
		func(x *SignedStoreWitness) { x.AuthorityGeneration++ },
		func(x *SignedStoreWitness) { x.CoreRevision++ },
		func(x *SignedStoreWitness) { x.Nonce = x.CoreIncarnation },
		func(x *SignedStoreWitness) { x.NotAfter++ },
	} {
		bad := w
		m(&bad)
		if ed25519.Verify(k.Public().(ed25519.PublicKey), StoreWitnessTranscript(bad), sig) {
			t.Fatalf("mutated Control witness has original signature: %+v", bad)
		}
	}
}

func TestLocalDeniedProfileHWMDigestMatchesControl(t *testing.T) {
	if got := deniedProfileDigest(nil); got != "eab4b2179450179f4800ff300bcc16116728c6dd60bf5ea2e10020b9ef0f5693" {
		t.Fatalf("empty denied profile HWM differs from Control: %s", got)
	}
	profile := "77777777-7777-4777-8777-777777777777"
	if got := deniedProfileDigest(map[string]uint64{profile: 7}); got != "4d9936f70da34e7684370bfad1a670bff318f24375aa34688f80a5720fa2a456" {
		t.Fatalf("revoked profile HWM differs from Control: %s", got)
	}
	if deniedProfileDigest(map[string]uint64{profile: 1}) == deniedProfileDigest(map[string]uint64{profile: 7}) {
		t.Fatal("different profile generations produced the same HWM")
	}
}
