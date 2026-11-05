package policy

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

const leaseAcceptanceBytes = 88

// SignedLeaseAcceptance proves that THIS pinned ElXray instance accepted a
// Control-signed, still-live lease into its actual enforcing rate limiter.
// A signed Control ticket merely delivered to an agent is not sufficient.
//
// Wire v1: core UUID[16], pinned node UUID[16], accepted Control sequence,
// signed lease expiry (Unix seconds), signed upload/download ceilings,
// applied policy revision and applied upload/download rates (seven u64).
// All integer fields are big-endian. A 64-byte Ed25519 core signature
// follows the 88-byte payload, bound to a fresh nonce and subscription ID.
//
// A lease proof does not count physical devices or authorize a rate grant.
// Control must still verify the assigned node/resource, monotonic sequence,
// current entitlement, policy revision, FUP and core identity.
func (m *Instance) SignedLeaseAcceptance(id, challenge string) ([]byte, error) {
	nonce, err := hex.DecodeString(challenge)
	if err != nil || len(challenge) != 32 || len(nonce) != 16 ||
		hex.EncodeToString(nonce) != challenge || id == "" ||
		len(id) > 1024 || strings.TrimSpace(id) != id {
		return nil, errors.New("invalid signed lease challenge")
	}
	m.subscriptionMu.Lock()
	defer m.subscriptionMu.Unlock()
	if len(m.leasePublicKey) != ed25519.PublicKeySize ||
		m.leaseNodeID == [16]byte{} ||
		m.store == nil || m.store.failed ||
		m.usageIncarnation == [16]byte{} {
		return nil, errors.New("durable core lease enforcement unavailable")
	}
	ticket, ok := m.leaseAccepted[id]
	policy, policyOK := m.subscriptionPolicies[id]
	if !ok || !policyOK || len(policy.Emails) == 0 || policy.Disabled ||
		ticket.Subscription != id || ticket.NodeID != m.leaseNodeID ||
		ticket.Sequence <= 0 || m.leaseSeq[id] != ticket.Sequence ||
		ticket.NotAfter <= time.Now().Unix()+1 ||
		ticket.CeilingUp <= 0 || ticket.CeilingDown <= 0 ||
		policy.Revision == 0 || policy.UplinkBps == 0 || policy.DownlinkBps == 0 ||
		policy.UplinkBps > uint64(ticket.CeilingUp) ||
		policy.DownlinkBps > uint64(ticket.CeilingDown) {
		return nil, errors.New("no currently accepted Control lease for subscription")
	}
	limits := m.subscriptions[strings.ToLower(policy.Emails[0])]
	if limits == nil {
		return nil, errors.New("subscription limiter is not enrolled")
	}
	if _, active := limits.ActiveLeaseDeadline(); !active {
		return nil, errors.New("Control lease not enforced by current core")
	}
	data := make([]byte, 0, leaseAcceptanceBytes)
	data = append(data, m.usageIncarnation[:]...)
	data = append(data, m.leaseNodeID[:]...)
	for _, field := range [7]uint64{
		uint64(ticket.Sequence), uint64(ticket.NotAfter),
		uint64(ticket.CeilingUp), uint64(ticket.CeilingDown),
		policy.Revision, policy.UplinkBps, policy.DownlinkBps,
	} {
		data = binary.BigEndian.AppendUint64(data, field)
	}
	message := fmt.Appendf(nil, "elx-lease-accept-v1\n%x\n%x\n%x", challenge, id, data)
	return append(data, ed25519.Sign(m.store.key, message)...), nil
}
