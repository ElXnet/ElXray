package policy

import (
	"context"
	"crypto/rand"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/subscriptionrate"
	"github.com/xtls/xray-core/features/policy"
)

// Instance is an instance of Policy manager.
type Instance struct {
	unmanaged            *subscriptionrate.Limits
	levels               map[uint32]*Policy
	system               *SystemPolicy
	subscriptions        map[string]*subscriptionrate.Limits
	subscriptionMu       sync.Mutex
	store                *policyStore
	usageIncarnation     [16]byte
	usageSequences       map[string]uint64
	subscriptionPolicies map[string]subscriptionrate.Policy
}

// New creates new Policy manager instance.
func New(ctx context.Context, config *Config) (*Instance, error) {
	subscriptions, err := BuildSubscriptionRates(config.Subscriptions)
	if err != nil {
		return nil, err
	}
	m := &Instance{
		levels:               make(map[uint32]*Policy),
		system:               config.System,
		subscriptions:        subscriptions,
		subscriptionPolicies: make(map[string]subscriptionrate.Policy),
		usageSequences:       make(map[string]uint64),
	}
	if config.RequireSubscription {
		m.unmanaged = subscriptionrate.New(0, 0)
		m.unmanaged.Update(0, 0, true)
	}
	for id, p := range config.Subscriptions {
		revision := p.Revision
		if revision == 0 {
			revision = 1
		}
		m.subscriptionPolicies[id] = subscriptionrate.Policy{ID: id, Emails: slices.Clone(p.Emails), UplinkBps: p.UplinkBps, DownlinkBps: p.DownlinkBps, Revision: revision, Disabled: p.Disabled}
	}
	if path := os.Getenv("ELXRAY_POLICY_STATE"); path != "" {
		if err := m.restorePolicies(path); err != nil {
			return nil, err
		}
		if _, err := rand.Read(m.usageIncarnation[:]); err != nil {
			return nil, err
		}
		m.usageIncarnation[6] = m.usageIncarnation[6]&0x0f | 0x40
		m.usageIncarnation[8] = m.usageIncarnation[8]&0x3f | 0x80
		for _, p := range m.subscriptionPolicies {
			m.subscriptions[strings.ToLower(p.Emails[0])].Update(p.UplinkBps, p.DownlinkBps, p.Disabled)
		}
	}
	if len(config.Level) > 0 {
		for lv, p := range config.Level {
			pp := defaultPolicy()
			pp.overrideWith(p)
			m.levels[lv] = pp
		}
	}

	return m, nil
}

// ForEmail returns the subscription's shared limits, or nil for an unmanaged identity.
func (m *Instance) ForEmail(email string) *subscriptionrate.Limits {
	if limits := m.subscriptions[strings.ToLower(email)]; limits != nil {
		return limits
	}
	return m.unmanaged
}

// Type implements common.HasType.
func (*Instance) Type() interface{} {
	return policy.ManagerType()
}

// ForLevel implements policy.Manager.
func (m *Instance) ForLevel(level uint32) policy.Session {
	if p, ok := m.levels[level]; ok {
		return p.ToCorePolicy()
	}
	return policy.SessionDefault()
}

// ForSystem implements policy.Manager.
func (m *Instance) ForSystem() policy.System {
	if m.system == nil {
		return policy.System{}
	}
	return m.system.ToCorePolicy()
}

// Start implements common.Runnable.Start().
func (m *Instance) Start() error {
	return nil
}

// Close implements common.Closable.Close().
func (m *Instance) Close() error {
	m.subscriptionMu.Lock()
	defer m.subscriptionMu.Unlock()
	if m.store != nil {
		m.store.failed = true
		return m.store.lock.Close()
	}
	return nil
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}
