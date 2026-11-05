package policy

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common/subscriptionrate"
	feature "github.com/xtls/xray-core/features/policy"
)

// ProveRateBarrier is deliberately disruptive only to THIS subscription:
// after the lower policy has been durably applied, it blocks new admissions,
// actively stops existing flows, waits for untrack, and only then signs a
// barrier that authorizes Control to lower its global committed rate ledger.
func (m *Instance) ProveRateBarrier(ctx context.Context, request feature.RateBarrierRequest) ([]byte, error) {
	if request.EntitlementID == uuid.Nil || request.NodeID == uuid.Nil ||
		request.ResourceID == uuid.Nil || request.OperationID == uuid.Nil ||
		request.Epoch <= 0 || request.Revision <= 0 || request.CoreRevision <= 1 ||
		request.Up < 0 || request.Down < 0 || request.Up > int64(subscriptionrate.MaxRate) ||
		request.Down > int64(subscriptionrate.MaxRate) ||
		(request.Up == 0) != (request.Down == 0) ||
		request.Subscription == "" || len(request.Subscription) > 1024 {
		return nil, errors.New("invalid rate barrier assignment")
	}
	m.subscriptionMu.Lock()
	p, ok := m.subscriptionPolicies[request.Subscription]
	if m.store == nil || m.store.failed || !ok || len(p.Emails) == 0 ||
		p.Revision != uint64(request.CoreRevision) {
		m.subscriptionMu.Unlock()
		return nil, errors.New("durable applied rate revision unavailable")
	}
	requiredUp, requiredDown := uint64(max(1, request.Up)), uint64(max(1, request.Down))
	if p.UplinkBps != requiredUp || p.DownlinkBps != requiredDown ||
		p.Disabled != (request.Up == 0) {
		m.subscriptionMu.Unlock()
		return nil, errors.New("actual live rate policy does not match barrier")
	}
	limits := m.subscriptions[strings.ToLower(p.Emails[0])]
	if limits == nil {
		m.subscriptionMu.Unlock()
		return nil, errors.New("rate limiter is not bound to policy")
	}
	store := m.store
	m.subscriptionMu.Unlock()
	// Closing old flows may take up to the RPC deadline. Never hold the
	// policy manager lock across it: other subscriptions must continue
	// renewing their signed Control leases and processing policy updates.
	if err := limits.DrainForRateBarrier(ctx); err != nil {
		return nil, fmt.Errorf("active subscription flows have not drained: %w", err)
	}
	m.subscriptionMu.Lock()
	defer m.subscriptionMu.Unlock()
	current, ok := m.subscriptionPolicies[request.Subscription]
	if !ok || m.store != store || m.store.failed || current.Revision != p.Revision ||
		current.UplinkBps != p.UplinkBps || current.DownlinkBps != p.DownlinkBps ||
		current.Disabled != p.Disabled {
		return nil, errors.New("rate barrier policy changed while draining")
	}
	message := fmt.Appendf(nil, "elx-rate-barrier-v1\n%s\n%s\n%s\n%s\n%d\n%d\n%d\n%d",
		request.EntitlementID, request.NodeID, request.ResourceID, request.OperationID,
		request.Epoch, request.Revision, request.Up, request.Down)
	return ed25519.Sign(m.store.key, message), nil
}
