package inbound

import (
	"context"
	"errors"
	"testing"

	"github.com/xtls/xray-core/common/serial"
)

type stage4FakeHandler struct {
	tag string
	startErr error
	started bool
	closed bool
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
	manager := &Manager{taggedHandlers: make(map[string]Handler), running: true}
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
	manager := &Manager{taggedHandlers: make(map[string]Handler)}
	handler := &stage4FakeHandler{tag: "bad-managed-inbound"}
	if err := manager.AddHandler(context.Background(), handler); err == nil {
		t.Fatal("managed inbound reload without policy authority was accepted")
	}
	if len(manager.ListHandlers(context.Background())) != 0 {
		t.Fatal("unauthorized handler entered the managed inbound registry")
	}
}
