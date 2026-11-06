package splithttp_test

import (
	"context"
	"testing"

	. "github.com/xtls/xray-core/transport/internet/splithttp"
)

type fakeRoundTripper struct{}

func (f *fakeRoundTripper) IsClosed() bool {
	return false
}

func TestMaxConnections(t *testing.T) {
	xmuxConfig := XmuxConfig{
		MaxConnections: &RangeConfig{From: 4, To: 4},
	}

	xmuxManager := NewXmuxManager(&xmuxConfig, func() XmuxConn {
		return &fakeRoundTripper{}
	})

	xmuxClients := make(map[interface{}]struct{})
	for i := 0; i < 8; i++ {
		xmuxClients[xmuxManager.GetXmuxClient(context.Background())] = struct{}{}
	}

	if len(xmuxClients) != 4 {
		t.Error("did not get 4 distinct clients, got ", len(xmuxClients))
	}
}

func TestCMaxReuseTimes(t *testing.T) {
	xmuxConfig := XmuxConfig{
		CMaxReuseTimes: &RangeConfig{From: 2, To: 2},
	}

	xmuxManager := NewXmuxManager(&xmuxConfig, func() XmuxConn {
		return &fakeRoundTripper{}
	})

	xmuxClients := make(map[interface{}]struct{})
	for i := 0; i < 64; i++ {
		xmuxClients[xmuxManager.GetXmuxClient(context.Background())] = struct{}{}
	}

	if len(xmuxClients) != 32 {
		t.Error("did not get 32 distinct clients, got ", len(xmuxClients))
	}
}

func TestMaxConcurrency(t *testing.T) {
	xmuxConfig := XmuxConfig{
		MaxConcurrency: &RangeConfig{From: 2, To: 2},
	}

	xmuxManager := NewXmuxManager(&xmuxConfig, func() XmuxConn {
		return &fakeRoundTripper{}
	})

	xmuxClients := make(map[interface{}]struct{})
	for i := 0; i < 64; i++ {
		xmuxClient := xmuxManager.GetXmuxClient(context.Background())
		xmuxClient.AddRunning()
		xmuxClients[xmuxClient] = struct{}{}
	}

	if len(xmuxClients) != 32 {
		t.Error("did not get 32 distinct clients, got ", len(xmuxClients))
	}
}

func TestDefault(t *testing.T) {
	for name, config := range map[string]*XmuxConfig{"nil": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			manager := NewXmuxManager(config, func() XmuxConn { return &fakeRoundTripper{} })
			first := manager.GetXmuxClient(context.Background())
			for i := 0; i < 64; i++ {
				client := manager.GetXmuxClient(context.Background())
				client.AddRunning()
				if client != first {
					t.Fatal("default policy replaced the existing connection")
				}
			}
		})
	}
}

func TestGetExistingXmuxClient(t *testing.T) {
	xmuxConfig := XmuxConfig{
		MaxConnections: &RangeConfig{From: 2, To: 2},
	}

	xmuxManager := NewXmuxManager(&xmuxConfig, func() XmuxConn {
		return &fakeRoundTripper{}
	})

	if xmuxManager.GetExistingXmuxClient(context.Background()) != nil {
		t.Error("got a client without creating one")
	}
	xmuxClient := xmuxManager.GetXmuxClient(context.Background())
	for i := 0; i < 4; i++ {
		if xmuxManager.GetExistingXmuxClient(context.Background()) != xmuxClient {
			t.Error("did not reuse the existing client")
		}
	}
}

func TestXmuxManagerKeepsReusePolicyAfterConfigMutation(t *testing.T) {
	config := XmuxConfig{CMaxReuseTimes: &RangeConfig{From: 2, To: 2}}
	manager := NewXmuxManager(&config, func() XmuxConn { return &fakeRoundTripper{} })
	config.CMaxReuseTimes.From = 1
	config.CMaxReuseTimes.To = 1
	first := manager.GetXmuxClient(context.Background())
	if got := manager.GetXmuxClient(context.Background()); got != first {
		t.Fatal("caller config mutation changed the manager's two-use connection policy")
	}
	if got := manager.GetXmuxClient(context.Background()); got == first {
		t.Fatal("connection was reused after its original two-use policy expired")
	}
}
