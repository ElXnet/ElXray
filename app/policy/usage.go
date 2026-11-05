package policy

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
)

// SignedUsage reports cumulative dispatcher payload for this policy manager
// incarnation. Counters survive policy edits, but reset with a new incarnation.
func (m *Instance) SignedUsage(id, challenge string) ([]byte, error) {
	m.subscriptionMu.Lock()
	defer m.subscriptionMu.Unlock()
	p, ok := m.subscriptionPolicies[id]
	if m.store == nil || m.store.failed || !ok {
		return nil, errors.New("usage unavailable")
	}
	limits := m.subscriptions[strings.ToLower(p.Emails[0])]
	m.usageSequences[id]++
	data := append([]byte{}, m.usageIncarnation[:]...)
	data = binary.BigEndian.AppendUint64(data, m.usageSequences[id])
	data = binary.BigEndian.AppendUint64(data, uint64(time.Now().UnixNano()))
	data = binary.BigEndian.AppendUint64(data, limits.Uplink.PayloadBytes())
	data = binary.BigEndian.AppendUint64(data, limits.Downlink.PayloadBytes())
	message := fmt.Appendf(nil, "elx-usage-v1\n%x\n%x\n%x", challenge, id, data)
	return append(data, ed25519.Sign(m.store.key, message)...), nil
}
