package policy

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// ManagedOperationEvidence is a versioned, core-signed APPLIED receipt. The
// JSON wrapper is transport only: the signature covers the exact v1 transcript
// and must be checked against the Control-pinned core key (never a key inside
// this object). No receipt is signed for an unresolved INTENT.
type ManagedOperationEvidence struct {
	Version uint32 `json:"version"`
	OperationID string `json:"operationId"`
	PayloadSHA256 string `json:"payloadSha256"`
	NodeID string `json:"nodeId"`
	ExecutorID string `json:"executorId"`
	ResourceID string `json:"resourceId"`
	AuthorityGeneration uint64 `json:"authorityGeneration"`
	Revision uint64 `json:"revision"`
	CoreIncarnation string `json:"coreIncarnation"`
	StoreID string `json:"storeId"`
	CompletedUnixNanos int64 `json:"completedUnixNanos"`
	Signature []byte `json:"signature"`
}

func (r ManagedOperationEvidence) transcript(challenge string) []byte {
	return fmt.Appendf(nil, "elx-applied-operation-v1\n%x\n%s\n%s\n%s\n%s\n%s\n%d\n%d\n%s\n%s\n%d",
		challenge, r.OperationID, r.PayloadSHA256, r.NodeID, r.ExecutorID, r.ResourceID,
		r.AuthorityGeneration, r.Revision, r.CoreIncarnation, r.StoreID, r.CompletedUnixNanos)
}

// SignedManagedReceipt requires a committed journal operation, matching
// durable current policy revision and a fresh exact 32-byte Control challenge.
func (m *Instance) SignedManagedReceipt(subscriptionID, operationID, challenge string) ([]byte, error) {
	nonce, err := hex.DecodeString(challenge)
	if err != nil || len(challenge) != 64 || len(nonce) != 32 ||
		hex.EncodeToString(nonce) != challenge || subscriptionID == "" ||
		strings.TrimSpace(subscriptionID) != subscriptionID {
		return nil, errors.New("invalid managed receipt challenge")
	}
	operation, err := uuid.Parse(operationID)
	if err != nil || operation == uuid.Nil || operation.String() != operationID {
		return nil, errors.New("invalid applied operation ID")
	}
	m.subscriptionMu.Lock()
	defer m.subscriptionMu.Unlock()
	if m.opJournal == nil || m.store == nil || m.store.failed ||
		len(m.store.key) != ed25519.PrivateKeySize || m.usageIncarnation == [16]byte{} {
		return nil, errors.New("managed durable receipt unavailable")
	}
	entry, found := m.opJournal.Get(operationID)
	policy, exists := m.subscriptionPolicies[subscriptionID]
	binding, bound := m.leaseBindings[subscriptionID]
	if !found || !exists || !bound || entry.State != "APPLIED" ||
		entry.Kind != "set-rate" || entry.CompletedUnixNanos <= 0 ||
		entry.ResourceID != binding.ResourceID.String() ||
		entry.ExecutorID != binding.ExecutorID.String() ||
		entry.NodeID != m.leaseNodeID.String() || entry.NewRevision != policy.Revision ||
		entry.AuthorityGeneration < binding.MinAuthorityGeneration {
		return nil, errors.New("no matching durable APPLIED managed operation")
	}
	receipt := ManagedOperationEvidence{
		Version: 1, OperationID: entry.OperationID,
		PayloadSHA256: entry.PayloadSHA256, NodeID: entry.NodeID,
		ExecutorID: entry.ExecutorID, ResourceID: entry.ResourceID,
		AuthorityGeneration: entry.AuthorityGeneration, Revision: entry.NewRevision,
		CoreIncarnation: uuid.UUID(m.usageIncarnation).String(),
		StoreID: m.opJournal.StoreID(), CompletedUnixNanos: entry.CompletedUnixNanos,
	}
	receipt.Signature = ed25519.Sign(m.store.key, receipt.transcript(challenge))
	return json.Marshal(receipt)
}
