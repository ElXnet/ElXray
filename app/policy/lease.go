package policy

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ControlLease is an absolute-expiry authorisation signed by the central
// Control key. Rate updates and their ACKs NEVER renew this lease.
type ControlLease struct {
	Version             uint32
	NodeID              uuid.UUID
	ResourceID          uuid.UUID
	ExecutorID          uuid.UUID
	AuthorityGeneration uint64
	Subscription        string
	Sequence            int64
	NotBefore           int64
	NotAfter            int64
	CeilingUp           int64
	CeilingDown         int64
	Signature           []byte
}

// ControlLeaseTranscript retains v2 bytes for archival fixtures only.
// Managed ElXray strictly accepts version 3, bound to core/resource/executor
// and a monotonically increasing Control-authorized grant epoch.
func ControlLeaseTranscript(t ControlLease) []byte {
	if t.Version == 3 {
		return fmt.Appendf(nil, "elx-control-lease-v3\n%s\n%s\n%s\n%s\n%d\n%d\n%d\n%d\n%d\n%d",
			t.NodeID, t.ResourceID, t.ExecutorID, t.Subscription,
			t.Sequence, t.NotBefore, t.NotAfter, t.CeilingUp, t.CeilingDown, t.AuthorityGeneration)
	}
	return fmt.Appendf(nil, "elx-control-lease-v2\n%s\n%s\n%d\n%d\n%d\n%d\n%d",
		t.NodeID, t.Subscription, t.Sequence, t.NotBefore, t.NotAfter, t.CeilingUp, t.CeilingDown)
}

// RenewControlLease verifies a server-signed ticket, enforces a short absolute
// lifetime, and only advances the deadline. A stale replay cannot move it.
func (m *Instance) RenewControlLease(t ControlLease) error {
	if len(m.leasePublicKey) != ed25519.PublicKeySize {
		return errors.New("Control lease enforcement is not configured")
	}
	now := time.Now()
	binding, bound := m.leaseBindings[t.Subscription]
	if !bound || t.Version != 3 || t.ResourceID != binding.ResourceID ||
		t.ExecutorID != binding.ExecutorID || t.AuthorityGeneration < binding.MinAuthorityGeneration ||
		t.NodeID != m.leaseNodeID || t.Subscription == "" || len(t.Subscription) > 1024 ||
		t.Sequence <= 0 || t.NotBefore > now.Unix()+5 ||
		t.NotBefore < now.Unix()-30 || t.NotAfter <= now.Unix() ||
		t.NotAfter-t.NotBefore <= 0 || t.NotAfter-t.NotBefore > 30 ||
		t.CeilingUp <= 0 || t.CeilingDown <= 0 ||
		len(t.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(m.leasePublicKey, ControlLeaseTranscript(t), t.Signature) {
		return errors.New("untrusted or expired Control lease")
	}
	m.subscriptionMu.Lock()
	defer m.subscriptionMu.Unlock()
	if m.store == nil || m.store.failed {
		return errors.New("durable ElXray policy state unavailable for lease")
	}
	p, ok := m.subscriptionPolicies[t.Subscription]
	if !ok || len(p.Emails) == 0 {
		return errors.New("unknown managed lease subscription")
	}
	// A valid signature is not sufficient if the running core is configured
	// above its actual reserved grant: never enable higher uncommitted rates.
	if p.UplinkBps > uint64(t.CeilingUp) || p.DownlinkBps > uint64(t.CeilingDown) {
		return errors.New("core subscription exceeds Control committed speed ceiling")
	}
	if t.AuthorityGeneration < m.leaseGeneration[t.Subscription] {
		return errors.New("stale Control grant authority generation")
	}
	if t.Sequence <= m.leaseSeq[t.Subscription] {
		return errors.New("replayed or stale Control lease sequence")
	}
	limits := m.subscriptions[strings.ToLower(p.Emails[0])]
	if limits == nil {
		return errors.New("unprovisioned subscription lease")
	}
	// Convert the signed wall-clock expiry to a monotonic local deadline.
	// Do not acknowledge a ticket until the limiter accepted that deadline.
	// A no-op renewal or a tripped lease is not proof of live admission.
	if !limits.RenewLease(time.Now().Add(time.Until(time.Unix(t.NotAfter, 0)))) {
		return errors.New("Control lease was not installed in live limiter")
	}
	if _, active := limits.ActiveLeaseDeadline(); !active {
		return errors.New("Control lease enforcement is not active")
	}
	m.leaseSeq[t.Subscription] = t.Sequence
	m.leaseGeneration[t.Subscription] = t.AuthorityGeneration
	m.leaseAccepted[t.Subscription] = t
	return nil
}
