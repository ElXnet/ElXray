package elxprovision

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestInstallReceiptGoldenAndTampering(t *testing.T) {
	grant, _ := testGrant(t)
	grant.Version, grant.Action, grant.Flow = 2, Install, "xtls-rprx-vision"
	digest := sha256.Sum256(grant.Transcript())
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	proof := InstallReceipt{
		Version: 1, OperationID: grant.OperationID, ProfileID: grant.ProfileID,
		NodeID: grant.NodeID, ExecutorID: grant.ExecutorID, ResourceID: grant.ResourceID,
		StoreID:             uuid.MustParse("66666666-6666-4666-8666-666666666666"),
		CoreIncarnation:     uuid.MustParse("77777777-7777-4777-8777-777777777777"),
		AuthorityGeneration: grant.AuthorityGeneration,
		PolicyRevision:      grant.PolicyRevision, TranscriptSHA256: hex.EncodeToString(digest[:]),
	}
	const golden = "d67adcec0bc268b849ff498f4e9821865698c823c62f107d2a6fe5f3c91fb253"
	actual := sha256.Sum256(proof.Transcript())
	if hex.EncodeToString(actual[:]) != golden {
		t.Fatalf("core/Control installed proof transcript drift: %x", actual)
	}
	proof.Signature = ed25519.Sign(key, proof.Transcript())
	pub := key.Public().(ed25519.PublicKey)
	if err := VerifyInstallReceipt(proof, grant, pub); err != nil {
		t.Fatalf("signed exact installed receipt rejected: %v", err)
	}
	for _, mutate := range []func(*InstallReceipt){
		func(p *InstallReceipt) { p.StoreID = uuid.New() },
		func(p *InstallReceipt) { p.CoreIncarnation = uuid.New() },
		func(p *InstallReceipt) { p.ProfileID = uuid.New() },
		func(p *InstallReceipt) { p.PolicyRevision++ },
		func(p *InstallReceipt) { p.Signature[0] ^= 1 },
	} {
		bad := proof
		bad.Signature = append([]byte(nil), proof.Signature...)
		mutate(&bad)
		if err := VerifyInstallReceipt(bad, grant, pub); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("forged technical installed proof accepted: %v", err)
		}
	}
}
