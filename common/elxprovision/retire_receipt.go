package elxprovision

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// RetireReceipt is a core-signed non-admitting proof of a permanently
// tombstoned technical VLESS UUID, after live validator absence is checked.
// This proof never authorizes Control to release a session owner's slot.
type RetireReceipt struct {
	Version             uint32
	OperationID         uuid.UUID
	ProfileID           uuid.UUID
	NodeID              uuid.UUID
	ExecutorID          uuid.UUID
	ResourceID          uuid.UUID
	StoreID             uuid.UUID
	CoreIncarnation     uuid.UUID
	AuthorityGeneration uint64
	PolicyRevision      uint64
	RetireGeneration    uint64
	TranscriptSHA256    string
	Signature           []byte
}

func (p RetireReceipt) Transcript() []byte {
	return []byte(strings.Join([]string{
		"elx-vless-retired-proof-v1", p.OperationID.String(),
		p.ProfileID.String(), p.NodeID.String(), p.ExecutorID.String(),
		p.ResourceID.String(), p.StoreID.String(), p.CoreIncarnation.String(),
		strconv.FormatUint(p.AuthorityGeneration, 10),
		strconv.FormatUint(p.PolicyRevision, 10),
		strconv.FormatUint(p.RetireGeneration, 10), p.TranscriptSHA256,
	}, "\n"))
}

func VerifyRetireReceipt(p RetireReceipt, grant Grant, key ed25519.PublicKey) error {
	if p.Version != 1 || grant.Version != 2 || grant.Action != Retire ||
		grant.ProfileGeneration < 2 || p.StoreID == uuid.Nil ||
		p.CoreIncarnation == uuid.Nil || p.OperationID != grant.OperationID ||
		p.ProfileID != grant.ProfileID || p.NodeID != grant.NodeID ||
		p.ExecutorID != grant.ExecutorID || p.ResourceID != grant.ResourceID ||
		p.AuthorityGeneration != grant.AuthorityGeneration ||
		p.PolicyRevision != grant.PolicyRevision ||
		p.RetireGeneration != grant.ProfileGeneration ||
		len(key) != ed25519.PublicKeySize || len(p.Signature) != ed25519.SignatureSize {
		return ErrUnauthorized
	}
	sum := sha256.Sum256(grant.Transcript())
	if p.TranscriptSHA256 != hex.EncodeToString(sum[:]) ||
		!ed25519.Verify(key, p.Transcript(), p.Signature) {
		return ErrUnauthorized
	}
	return nil
}
