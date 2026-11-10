package elxprovision

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestControlProfileWireRejectsForgedOrAmbiguousJob(t *testing.T) {
	grant, private := testGrant(t)
	pinned := private.Public().(ed25519.PublicKey)
	sig := append([]byte(nil), grant.Signature...)
	grant.Signature = nil // Control signs the outer envelope only.
	job := ControlJob{Grant: grant, Signature: sig}
	raw, err := json.Marshal(job)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1700000008, 0)
	verified, err := DecodeControlJob(raw, pinned,
		grant.NodeID, grant.ExecutorID, grant.ResourceID, now)
	if err != nil || verified.ProfileID != grant.ProfileID ||
		string(verified.Signature) != string(sig) {
		t.Fatalf("correctly signed technical preparation failed: %+v %v", verified, err)
	}
	for name, mutate := range map[string]func(*ControlJob){
		"foreign-executor": func(x *ControlJob) { x.Grant.ExecutorID = x.Grant.NodeID },
		"foreign-resource": func(x *ControlJob) { x.Grant.ResourceID = x.Grant.NodeID },
		"wrong-operation": func(x *ControlJob) { x.Grant.OperationID = x.Grant.NodeID },
		"wrong-epoch": func(x *ControlJob) { x.Grant.AuthorityGeneration++ },
		"wrong-inbound": func(x *ControlJob) { x.Grant.InboundTag = "fake-inbound" },
		"bad-signature": func(x *ControlJob) { x.Signature[0] ^= 1 },
		"nested-signature": func(x *ControlJob) { x.Grant.Signature = sig },
	}{
		t.Run(name, func(t *testing.T) {
			bad := job
			bad.Signature = append([]byte(nil), sig...)
			mutate(&bad)
			encoded, _ := json.Marshal(bad)
			if _, err := DecodeControlJob(encoded, pinned,
				grant.NodeID, grant.ExecutorID, grant.ResourceID, now); err == nil {
				t.Fatal("foreign or ambiguous technical preparation accepted")
			}
		})
	}
	if _, err := DecodeControlJob(append(raw, []byte("true")...), pinned,
		grant.NodeID, grant.ExecutorID, grant.ResourceID, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("multiple JSON documents accepted: %v", err)
	}
	if _, err := DecodeControlJob(append(raw[:len(raw)-1], []byte(`,"unexpected":1}`)...), pinned,
		grant.NodeID, grant.ExecutorID, grant.ResourceID, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown envelope field accepted: %v", err)
	}
	if _, err := DecodeControlJob(raw, pinned,
		grant.NodeID, grant.ExecutorID, grant.ResourceID,
		time.Unix(grant.NotAfter+1, 0)); err == nil {
		t.Fatal("expired job accepted")
	}
}
