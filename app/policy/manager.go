package policy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/elxsecurity"
	"github.com/xtls/xray-core/common/sessionfence"
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
	profileGate          *sessionfence.Registry
	leasePublicKey       ed25519.PublicKey
	leaseNodeID          uuid.UUID
	leaseBindings        map[string]leaseBinding
	leaseGeneration      map[string]uint64
	leaseSeq             map[string]int64
	leaseAccepted        map[string]ControlLease
	leaseCancel          context.CancelFunc
}

// New creates new Policy manager instance.
func New(ctx context.Context, config *Config) (*Instance, error) {
	if config == nil {
		return nil, errors.New("policy configuration is required")
	}
	mode := os.Getenv("ELXRAY_MODE")
	if mode != "" && mode != "managed" && mode != "standalone" {
		return nil, errors.New("unsupported ElXray execution mode")
	}
	// A partially provisioned managed node may NEVER silently become
	// standalone if a single lease flag, key, node or agent identity is lost.
	managedHints := []string{
		"ELXRAY_REQUIRE_CONTROL_LEASE", "ELXRAY_CONTROL_LEASE_PUBLIC_KEY",
		"ELXRAY_CONTROL_LEASE_NODE_UUID", "ELXRAY_CONTROL_LEASE_BINDINGS_FILE",
		"ELXRAY_AGENT_UID", "ELXRAY_AGENT_GID",
	}
	if mode != "managed" {
		for _, key := range managedHints {
			if os.Getenv(key) != "" {
				return nil, errors.New("managed identity hints require explicit ELXRAY_MODE=managed")
			}
		}
	}
	if mode == "managed" {
		if os.Getenv("ELXRAY_REQUIRE_CONTROL_LEASE") != "1" {
			return nil, errors.New("managed ElXray requires signed Control lease enforcement")
		}
		if _, _, err := elxsecurity.AgentIdentity(); err != nil {
			return nil, err
		}
	}
	if mode == "managed" {
		// A rate of zero means UNLIMITED to upstream Xray. An initial
		// unmanaged/legacy JSON policy must never become an unlimited
		// session merely because a valid finite Control lease is delivered.
		for id, p := range config.Subscriptions {
			if p == nil || p.UplinkBps == 0 || p.DownlinkBps == 0 {
				return nil, errors.New("managed subscription " + id + " requires finite positive rates")
			}
		}
	}
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
		profileGate:          sessionfence.New(),
	}
	if config.RequireSubscription {
		m.unmanaged = subscriptionrate.New(0, 0)
		m.unmanaged.Update(0, 0, true)
	}
	if mode == "managed" {
		if !config.RequireSubscription || len(m.subscriptions) == 0 {
			return nil, errors.New("Control lease enforcement requires managed subscriptions")
		}
		if os.Getenv("ELXRAY_POLICY_STATE") == "" {
			return nil, errors.New("Control lease enforcement requires durable policy state")
		}
		pub, err := base64.StdEncoding.DecodeString(os.Getenv("ELXRAY_CONTROL_LEASE_PUBLIC_KEY"))
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, errors.New("Control lease public key must be provisioned")
		}
		node, err := uuid.Parse(os.Getenv("ELXRAY_CONTROL_LEASE_NODE_UUID"))
		if err != nil || node == uuid.Nil {
			return nil, errors.New("Control lease requires a pinned node UUID")
		}
		bindings, err := loadManagedLeaseBindings(config.Subscriptions)
		if err != nil {
			return nil, err
		}
		m.leasePublicKey = ed25519.PublicKey(pub)
		m.leaseNodeID = node
		m.leaseBindings = bindings
		m.leaseGeneration = make(map[string]uint64)
		m.leaseSeq = make(map[string]int64)
		m.leaseAccepted = make(map[string]ControlLease)
		seen := make(map[*subscriptionrate.Limits]bool)
		for _, limit := range m.subscriptions {
			if !seen[limit] {
				limit.RequireLease()
				seen[limit] = true
			}
		}
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
	if len(m.leasePublicKey) == 0 {
		return nil
	}
	m.subscriptionMu.Lock()
	if m.leaseCancel != nil {
		m.subscriptionMu.Unlock()
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.leaseCancel = cancel
	m.subscriptionMu.Unlock()
	go func() {
		t := time.NewTicker(100 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				seen := make(map[*subscriptionrate.Limits]bool)
				for _, limits := range m.subscriptions {
					if !seen[limits] {
						limits.SweepLease(now)
						seen[limits] = true
					}
				}
			}
		}
	}()
	return nil
}

// Close implements common.Closable.Close().
func (m *Instance) Close() error {
	m.subscriptionMu.Lock()
	defer m.subscriptionMu.Unlock()
	if m.leaseCancel != nil {
		m.leaseCancel()
		m.leaseCancel = nil
	}
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
