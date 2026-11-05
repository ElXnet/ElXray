package policy

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

const pressureEvidenceBytes = 120

// SignedPressure returns a nonce-bound, Ed25519-signed measurement for the
// Control-assigned subscription and this exact running ElXray incarnation.
// A sample is diagnostic only: it does not grant any subscription bandwidth.
//
// The 120-byte v1 payload contains the core UUID, sequence, Unix-nanosecond
// sample time, policy revision, both applied rates and four upload plus four
// download limiter counters. The Ed25519 signature occupies the next 64 bytes.
//
// // All integers are big endian. The signature covers the entire data,
// canonical subscription ID, and a fresh Control-issued 16-byte challenge.
func (m *Instance) SignedPressure(id, challenge string) ([]byte, error) {
	nonce, err := hex.DecodeString(challenge)
	if err != nil || len(challenge) != 32 || len(nonce) != 16 ||
		hex.EncodeToString(nonce) != challenge ||
		id == "" || len(id) > 1024 || strings.TrimSpace(id) != id {
		return nil, errors.New("invalid pressure challenge")
	}
	m.subscriptionMu.Lock()
	defer m.subscriptionMu.Unlock()
	p, ok := m.subscriptionPolicies[id]
	if m.store == nil || m.store.failed || !ok || len(p.Emails) == 0 ||
		m.usageIncarnation == [16]byte{} ||
		m.usageSequences[id] == math.MaxUint64 {
		return nil, errors.New("durable pressure source unavailable")
	}
	limits := m.subscriptions[strings.ToLower(p.Emails[0])]
	if limits == nil || limits.Uplink == nil || limits.Downlink == nil {
		return nil, errors.New("subscription pressure counters unavailable")
	}
	u, d := limits.Uplink.Pressure(), limits.Downlink.Pressure()
	// A negative gauge is never valid evidence. Do not wrap it to uint64.
	if u.ActiveWaiters < 0 || d.ActiveWaiters < 0 {
		return nil, errors.New("invalid pressure gauge")
	}
	m.usageSequences[id]++
	data := make([]byte, 0, pressureEvidenceBytes)
	data = append(data, m.usageIncarnation[:]...)
	data = binary.BigEndian.AppendUint64(data, m.usageSequences[id])
	data = binary.BigEndian.AppendUint64(data, uint64(time.Now().UnixNano()))
	data = binary.BigEndian.AppendUint64(data, p.Revision)
	data = binary.BigEndian.AppendUint64(data, p.UplinkBps)
	data = binary.BigEndian.AppendUint64(data, p.DownlinkBps)
	for _, counters := range [2][4]uint64{
		{u.PayloadBytes, u.BlockedCalls, u.BlockedNanos, uint64(u.ActiveWaiters)},
		{d.PayloadBytes, d.BlockedCalls, d.BlockedNanos, uint64(d.ActiveWaiters)},
	} {
		for _, counter := range counters {
			data = binary.BigEndian.AppendUint64(data, counter)
		}
	}
	transcript := fmt.Appendf(nil, "elx-pressure-v1\n%x\n%x\n%x", challenge, id, data)
	return append(data, ed25519.Sign(m.store.key, transcript)...), nil
}
