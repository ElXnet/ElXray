package elxprovision

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/google/uuid"
)

// ControlJob uses the exact JSON envelope issued by the authenticated
// Control PolicyDelivery/TechnicalProfileNext RPC. The envelope is not the
// authority: only the pre-provisioned Control public key and exact pinned
// node/resource/executor are. No embedded key can override those.
type ControlJob struct {
	Grant Grant
	Signature []byte
}

// DecodeControlJob refuses unknown fields, trailing JSON, unsigned values,
// foreign executor/node/resource, stale generation and expired grants. No
// live user mutation or device admission is performed by this function.
func DecodeControlJob(raw []byte, publicKey ed25519.PublicKey,
	node, executor, resource uuid.UUID, now time.Time) (Grant, error) {
	if len(raw) == 0 || len(raw) > 4096 {
		return Grant{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var envelope ControlJob
	if err := decoder.Decode(&envelope); err != nil {
		return Grant{}, ErrInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Grant{}, ErrInvalid
	}
	if len(envelope.Grant.Signature) != 0 {
		// The only allowed signature is the outer Control-issued one.
		// A nested or contradictory signature could create ambiguous jobs.
		return Grant{}, ErrInvalid
	}
	envelope.Grant.Signature = append([]byte(nil), envelope.Signature...)
	if err := Verify(envelope.Grant, publicKey, node, executor, resource, now); err != nil {
		return Grant{}, err
	}
	return envelope.Grant, nil
}
