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

// ProveRateBarrier signs a reduced rate only after the exact durable policy
// has been applied and earlier dispatcher payload transfers have quiesced.
// Positive-rate reductions briefly pause new chunks without closing sessions.
// Full disables keep the stricter signed flow-drain protocol.
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
	// Do not hold the policy manager lock while waiting for any old payload
	// transfer to finish: unrelated subscriptions and signed leases must
	// remain responsive. The callback revalidates the exact durable revision
	// under the lock before signing, while new transfers are still paused.
	sign := func() ([]byte, error) {
		m.subscriptionMu.Lock()
		defer m.subscriptionMu.Unlock()
		current, ok := m.subscriptionPolicies[request.Subscription]
		if !ok || m.store != store || m.store.failed || current.Revision != p.Revision ||
			current.UplinkBps != p.UplinkBps || current.DownlinkBps != p.DownlinkBps ||
			current.Disabled != p.Disabled {
			return nil, errors.New("rate barrier policy changed before proof")
		}
		message := fmt.Appendf(nil, "elx-rate-barrier-v1\n%s\n%s\n%s\n%s\n%d\n%d\n%d\n%d",
			request.EntitlementID, request.NodeID, request.ResourceID, request.OperationID,
			request.Epoch, request.Revision, request.Up, request.Down)
		return ed25519.Sign(m.store.key, message), nil
	}
	if request.Up == 0 {
		// A disable/revoke is not an ordinary speed reduction. For release
		// of its entitlement, require every old flow to stop completely.
		if err := limits.DrainForRateBarrier(ctx); err != nil {
			return nil, fmt.Errorf("disabled subscription flows have not drained: %w", err)
		}
		return sign()
	}
	proof, err := limits.WithQuietRateBarrier(ctx, sign)
	if err != nil {
		return nil, fmt.Errorf("in-place lower-rate barrier not established: %w", err)
	}
	return proof, nil
}
