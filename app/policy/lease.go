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
	NodeID       uuid.UUID
	Subscription string
	Sequence     int64
	NotBefore    int64
	NotAfter     int64
	Signature    []byte
}

func ControlLeaseTranscript(t ControlLease) []byte {
	return fmt.Appendf(nil, "elx-control-lease-v1\n%s\n%s\n%d\n%d\n%d",
		t.NodeID, t.Subscription, t.Sequence, t.NotBefore, t.NotAfter)
}

// RenewControlLease verifies a server-signed ticket, enforces a short absolute
// lifetime, and only advances the deadline. A stale replay cannot move it.
func (m *Instance) RenewControlLease(t ControlLease) error {
	if len(m.leasePublicKey) != ed25519.PublicKeySize {
		return errors.New("Control lease enforcement is not configured")
	}
	now := time.Now()
	if t.NodeID != m.leaseNodeID || t.Subscription == "" || len(t.Subscription) > 1024 ||
		t.Sequence <= 0 || t.NotBefore > now.Unix()+5 ||
		t.NotBefore < now.Unix()-30 || t.NotAfter <= now.Unix() ||
		t.NotAfter-t.NotBefore <= 0 || t.NotAfter-t.NotBefore > 30 ||
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
	if t.Sequence <= m.leaseSeq[t.Subscription] {
		return errors.New("replayed or stale Control lease sequence")
	}
	m.leaseSeq[t.Subscription] = t.Sequence
	limits := m.subscriptions[strings.ToLower(p.Emails[0])]
	if limits == nil {
		return errors.New("unprovisioned subscription lease")
	}
	// Convert the wall-clock signed expiry to a monotonic local deadline.
	// An NTP adjustment after receipt must not prolong a partitioned lease.
	limits.RenewLease(time.Now().Add(time.Until(time.Unix(t.NotAfter, 0))))
	return nil
}
