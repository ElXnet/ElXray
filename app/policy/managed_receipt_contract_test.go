package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestManagedAppliedReceiptGoldenTranscript(t *testing.T) {
	evidence := ManagedOperationEvidence{
		Version:             1,
		OperationID:         "11111111-1111-4111-8111-111111111111",
		PayloadSHA256:       "4255081ce063d5fc3a34d2099448e626e4202b80197d47d26b200ec2d19193bd",
		NodeID:              "22222222-2222-4222-8222-222222222222",
		ResourceID:          "33333333-3333-4333-8333-333333333333",
		ExecutorID:          "44444444-4444-4444-8444-444444444444",
		AuthorityGeneration: 9, Revision: 2,
		CoreIncarnation:    "55555555-5555-4555-8555-555555555555",
		StoreID:            "66666666-6666-4666-8666-666666666666",
		CompletedUnixNanos: 1700000000000000000,
	}
	const challenge = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	got := sha256.Sum256(evidence.transcript(challenge))
	if hex.EncodeToString(got[:]) != "d354a37354ec0d68fa97f37352cb8cc456897832947772eee61d8ed81a47b8f7" {
		t.Fatalf("core signed applied operation transcript drifted from Control: %x", got)
	}
}
