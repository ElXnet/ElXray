package elxprovision

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// InstallReceipt is an independently core-signed statement about a *live*
// VLESS technical user. It is not owner admission or permission for payload.
// No agent-supplied fields or unsigned readback are sufficient for Control.
type InstallReceipt struct {
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
	TranscriptSHA256    string
	Signature           []byte
}

// Transcript is shared verbatim with ElX-control/corepolicy. The exact
// accepted INSTALL job digest binds subscription, inbound, email and Flow.
func (p InstallReceipt) Transcript() []byte {
	return []byte(strings.Join([]string{
		"elx-vless-installed-proof-v1", p.OperationID.String(),
		p.ProfileID.String(), p.NodeID.String(), p.ExecutorID.String(),
		p.ResourceID.String(), p.StoreID.String(), p.CoreIncarnation.String(),
		strconv.FormatUint(p.AuthorityGeneration, 10),
		strconv.FormatUint(p.PolicyRevision, 10), p.TranscriptSHA256,
	}, "\n"))
}

// VerifyInstallReceipt enforces both Control's exact grant and the
// independently provisioned core public key. It never accepts a proof as
// evidence that any device has authenticated or occupied a VPN session slot.
func VerifyInstallReceipt(p InstallReceipt, grant Grant, key ed25519.PublicKey) error {
	if p.Version != 1 || grant.Version != 2 || grant.Action != Install ||
		grant.ProfileID == uuid.Nil || p.StoreID == uuid.Nil ||
		p.CoreIncarnation == uuid.Nil || p.NodeID != grant.NodeID ||
		p.ExecutorID != grant.ExecutorID || p.ResourceID != grant.ResourceID ||
		p.ProfileID != grant.ProfileID || p.OperationID != grant.OperationID ||
		p.AuthorityGeneration != grant.AuthorityGeneration ||
		p.PolicyRevision != grant.PolicyRevision || len(key) != ed25519.PublicKeySize ||
		len(p.Signature) != ed25519.SignatureSize {
		return ErrUnauthorized
	}
	hash := sha256.Sum256(grant.Transcript())
	if p.TranscriptSHA256 != hex.EncodeToString(hash[:]) ||
		!ed25519.Verify(key, p.Transcript(), p.Signature) {
		return ErrUnauthorized
	}
	return nil
}
