package inbound

import (
	"context"
	"os"
	"sync"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	featurepolicy "github.com/xtls/xray-core/features/policy"
)

// Manager manages all inbound handlers.
type Manager struct {
	access           sync.RWMutex
	untaggedHandlers []inbound.Handler
	taggedHandlers   map[string]inbound.Handler
	running          bool
}

// New returns a new Manager for inbound handlers.
func New(ctx context.Context, config *proxyman.InboundConfig) (*Manager, error) {
	m := &Manager{
		taggedHandlers: make(map[string]inbound.Handler),
	}
	return m, nil
}

// Type implements common.HasType.
func (*Manager) Type() interface{} {
	return inbound.ManagerType()
}

// AddHandler implements inbound.Manager. In technical managed mode the
// policy-side admission guard holds the signed mutation mutex through
// registration/Start, preventing a stale handler from racing INSTALL/RETIRE.
func (m *Manager) AddHandler(ctx context.Context, handler inbound.Handler) error {
	if handler == nil {
		return errors.New("nil inbound handler")
	}
	register := func() error {
		m.access.Lock()
		defer m.access.Unlock()

		tag := handler.Tag()
		if tag != "" {
			if _, found := m.taggedHandlers[tag]; found {
				return errors.New("existing tag found: " + tag)
			}
			m.taggedHandlers[tag] = handler
		} else {
			m.untaggedHandlers = append(m.untaggedHandlers, handler)
		}
		if m.running {
			if err := handler.Start(); err != nil {
				// The failed handler is not an admitted/live inbound.
				if tag != "" {
					delete(m.taggedHandlers, tag)
				} else {
					m.untaggedHandlers = m.untaggedHandlers[:len(m.untaggedHandlers)-1]
				}
				_ = handler.Close()
				return err
			}
		}
		return nil
	}
	server := core.FromContext(ctx)
	if server != nil {
		if pm, ok := server.GetFeature(featurepolicy.ManagerType()).(interface {
			WithTechnicalInboundRegistration(string, bool, func() []*protocol.MemoryUser, func() error) error
		}); ok {
			var users func() []*protocol.MemoryUser
			isVLESS := false
			if source, ok := handler.(interface{ ElXVLESSTechnicalUsers() any }); ok {
				if raw := source.ElXVLESSTechnicalUsers(); raw != nil {
					validator, ok := raw.(interface {
						GetUsers(context.Context) []*protocol.MemoryUser
					})
					if !ok {
						return errors.New("uninspectable managed VLESS users")
					}
					isVLESS = true
					users = func() []*protocol.MemoryUser { return validator.GetUsers(ctx) }
				}
			}
			return pm.WithTechnicalInboundRegistration(handler.Tag(), isVLESS, users, register)
		}
	}
	// A managed technical node may not lose its policy extension and fall
	// back to unsigned, unchecked handler mutation.
	if os.Getenv("ELXRAY_TECHNICAL_PROVISIONING") == "1" {
		return errors.New("managed technical inbound guard unavailable")
	}
	return register()
}

// GetHandler implements inbound.Manager.
func (m *Manager) GetHandler(ctx context.Context, tag string) (inbound.Handler, error) {
	m.access.RLock()
	defer m.access.RUnlock()

	handler, found := m.taggedHandlers[tag]
	if !found {
		return nil, errors.New("handler not found: ", tag)
	}
	return handler, nil
}

// RemoveHandler implements inbound.Manager. No in-place listener removal
// may make a durable technical PREPARED/INSTALLED identity disappear while
// its Control operation or live connection remains authoritative.
func (m *Manager) RemoveHandler(ctx context.Context, tag string) error {
	if tag == "" {
		return common.ErrNoClue
	}
	remove := func() error {
		m.access.Lock()
		defer m.access.Unlock()
		if handler, found := m.taggedHandlers[tag]; found {
			if err := handler.Close(); err != nil {
				errors.LogWarningInner(ctx, err, "failed to close handler ", tag)
			}
			delete(m.taggedHandlers, tag)
			return nil
		}
		return common.ErrNoClue
	}
	server := core.FromContext(ctx)
	if server != nil {
		if pm, ok := server.GetFeature(featurepolicy.ManagerType()).(interface {
			WithTechnicalInboundRemoval(string, func() error) error
		}); ok {
			return pm.WithTechnicalInboundRemoval(tag, remove)
		}
	}
	if os.Getenv("ELXRAY_TECHNICAL_PROVISIONING") == "1" {
		return errors.New("managed technical inbound removal guard unavailable")
	}
	return remove()
}

// ListHandlers implements inbound.Manager.
func (m *Manager) ListHandlers(ctx context.Context) []inbound.Handler {
	m.access.RLock()
	defer m.access.RUnlock()

	response := make([]inbound.Handler, len(m.untaggedHandlers))
	copy(response, m.untaggedHandlers)

	for _, v := range m.taggedHandlers {
		response = append(response, v)
	}

	return response
}

// Start implements common.Runnable.
func (m *Manager) Start() error {
	m.access.Lock()
	defer m.access.Unlock()

	m.running = true

	for _, handler := range m.taggedHandlers {
		if err := handler.Start(); err != nil {
			return err
		}
	}

	for _, handler := range m.untaggedHandlers {
		if err := handler.Start(); err != nil {
			return err
		}
	}
	return nil
}

// Close implements common.Closable.
func (m *Manager) Close() error {
	m.access.Lock()
	defer m.access.Unlock()

	m.running = false

	var errs []interface{}
	for _, handler := range m.taggedHandlers {
		if err := handler.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	for _, handler := range m.untaggedHandlers {
		if err := handler.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errors.New("failed to close all handlers").Base(errors.New(serial.Concat(errs...)))
	}

	return nil
}

// NewHandler creates a new inbound.Handler based on the given config.
func NewHandler(ctx context.Context, config *core.InboundHandlerConfig) (inbound.Handler, error) {
	rawReceiverSettings, err := config.ReceiverSettings.GetInstance()
	if err != nil {
		return nil, err
	}
	proxySettings, err := config.ProxySettings.GetInstance()
	if err != nil {
		return nil, err
	}
	tag := config.Tag

	receiverSettings, ok := rawReceiverSettings.(*proxyman.ReceiverConfig)
	if !ok {
		return nil, errors.New("not a ReceiverConfig")
	}

	streamSettings := receiverSettings.StreamSettings
	if streamSettings != nil && streamSettings.SocketSettings != nil {
		ctx = session.ContextWithSockopt(ctx, &session.Sockopt{
			Mark: streamSettings.SocketSettings.Mark,
		})
	}
	if streamSettings != nil && (streamSettings.ProtocolName == "splithttp" || streamSettings.ProtocolName == "masque") {
		ctx = session.ContextWithAllowedNetwork(ctx, net.Network_UDP)
	}

	return NewAlwaysOnInboundHandler(ctx, tag, receiverSettings, proxySettings)
}

func init() {
	common.Must(common.RegisterConfig((*proxyman.InboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*proxyman.InboundConfig))
	}))
	common.Must(common.RegisterConfig((*core.InboundHandlerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewHandler(ctx, config.(*core.InboundHandlerConfig))
	}))
}
