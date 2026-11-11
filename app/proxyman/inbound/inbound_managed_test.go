package inbound

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	featureinbound "github.com/xtls/xray-core/features/inbound"
)

type stage4FakeHandler struct {
	tag      string
	startErr error
	started  bool
	closed   bool
}

func (h *stage4FakeHandler) Tag() string { return h.tag }
func (h *stage4FakeHandler) Start() error {
	h.started = true
	return h.startErr
}
func (h *stage4FakeHandler) Close() error {
	h.closed = true
	return nil
}
func (*stage4FakeHandler) ReceiverSettings() *serial.TypedMessage { return nil }
func (*stage4FakeHandler) ProxySettings() *serial.TypedMessage { return nil }

func TestHotReloadFailedInboundStartIsNeverPublished(t *testing.T) {
	t.Setenv("ELXRAY_TECHNICAL_PROVISIONING", "")
	manager := &Manager{taggedHandlers: make(map[string]featureinbound.Handler), running: true}
	broken := &stage4FakeHandler{tag: "reloaded", startErr: errors.New("test start failure")}
	if err := manager.AddHandler(context.Background(), broken); err == nil {
		t.Fatal("failed hot reload succeeded")
	}
	if !broken.started || !broken.closed {
		t.Fatal("failed inbound start was not closed")
	}
	if len(manager.ListHandlers(context.Background())) != 0 {
		t.Fatal("partially started hot reload remained discoverable")
	}
	ok := &stage4FakeHandler{tag: "reloaded"}
	if err := manager.AddHandler(context.Background(), ok); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.GetHandler(context.Background(), "reloaded"); err != nil {
		t.Fatal("failed start permanently poisoned inbound tag: ", err)
	}
}

func TestManagedHotReloadWithoutPolicyGuardFailsClosed(t *testing.T) {
	t.Setenv("ELXRAY_TECHNICAL_PROVISIONING", "1")
	manager := &Manager{taggedHandlers: make(map[string]featureinbound.Handler)}
	handler := &stage4FakeHandler{tag: "bad-managed-inbound"}
	if err := manager.AddHandler(context.Background(), handler); err == nil {
		t.Fatal("managed inbound reload without policy authority was accepted")
	}
	if len(manager.ListHandlers(context.Background())) != 0 {
		t.Fatal("unauthorized handler entered the managed inbound registry")
	}
}

type stage4LockProbe struct {
	*stage4FakeHandler
	manager *Manager
}

func (h *stage4LockProbe) Close() error {
	// A real inbound teardown can call policy/manager code. Closing it while
	// holding Manager.access would block this exact callback indefinitely.
	h.manager.ListHandlers(context.Background())
	h.closed = true
	return nil
}

func TestRemovedInboundClosesOutsideRegistryLock(t *testing.T) {
	t.Setenv("ELXRAY_TECHNICAL_PROVISIONING", "")
	manager := &Manager{taggedHandlers: make(map[string]featureinbound.Handler)}
	probe := &stage4LockProbe{
		stage4FakeHandler: &stage4FakeHandler{tag: "close-probe"},
		manager: manager,
	}
	if err := manager.AddHandler(context.Background(), probe); err != nil {
		t.Fatal(err)
	}
	completed := make(chan error, 1)
	go func() { completed <- manager.RemoveHandler(context.Background(), probe.tag) }()
	select {
	case err := <-completed:
		if err != nil || !probe.closed {
			t.Fatalf("unpublished handler was not safely closed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handler teardown deadlocked while holding inbound registry lock")
	}
	if len(manager.ListHandlers(context.Background())) != 0 {
		t.Fatal("removed handler still visible to signed operations")
	}
}

func TestCoreInboundManagerBindsOwnerEvenWithoutRuntimeCallerContext(t *testing.T) {
	t.Setenv("ELXRAY_TECHNICAL_PROVISIONING", "")
	server, err := core.New(&core.Config{})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := core.CreateObject(server, &proxyman.InboundConfig{})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := manager.(*Manager)
	if !ok || got.owner != server {
		t.Fatal("inbound manager lost core identity during construction")
	}
}
