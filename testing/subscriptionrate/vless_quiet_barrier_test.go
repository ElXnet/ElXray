package subscriptionrate_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	apppolicy "github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/subscriptionrate"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	featurepolicy "github.com/xtls/xray-core/features/policy"
	_ "github.com/xtls/xray-core/main/distro/all"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/encoding"
	"github.com/xtls/xray-core/proxy/vless/inbound"
	"github.com/xtls/xray-core/testing/servers/tcp"
)

// The VPN must keep an authenticated VLESS TCP session usable when the same
// live subscription has its limits reduced. This is an in-process network
// fixture, not a claim about external wire-rate or multi-node failover.
func TestVLESSSessionSurvivesQuietRateBarrier(t *testing.T) {
	target, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = target.Close() })
	go func() {
		for {
			conn, err := target.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	id := uuid.New()
	port := tcp.PickPort()
	server, err := core.New(&core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(&apppolicy.Config{
				RequireSubscription: true,
				Subscriptions: map[string]*apppolicy.SubscriptionPolicy{
					"account": {
						Emails: []string{"member"}, UplinkBps: 100000,
						DownlinkBps: 100000, Revision: 1,
					},
				},
			}),
		},
		Inbound: []*core.InboundHandlerConfig{{
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				Listen:   net.NewIPOrDomain(net.LocalHostIP),
				PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(port)}},
			}),
			ProxySettings: serial.ToTypedMessage(&inbound.Config{
				Users: []*protocol.User{{
					Email:   "member",
					Account: serial.ToTypedMessage(&vless.Account{Id: id.String()}),
				}},
			}),
		}},
		Outbound: []*core.OutboundHandlerConfig{{
			ProxySettings: serial.ToTypedMessage(&freedom.Config{
				FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
			}),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	manager, ok := server.GetFeature(featurepolicy.ManagerType()).(*apppolicy.Instance)
	if !ok {
		t.Fatal("server did not expose the bound policy manager")
	}
	conn, err := stdnet.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	request := &protocol.RequestHeader{
		Version: 0, Command: protocol.RequestCommandTCP,
		Address: net.DestinationFromAddr(target.Addr()).Address,
		Port:    net.DestinationFromAddr(target.Addr()).Port,
		User: &protocol.MemoryUser{
			Email:   "ignored-client-email",
			Account: &vless.MemoryAccount{ID: protocol.NewID(id)},
		},
	}
	if err := encoding.EncodeRequestHeader(conn, request, &encoding.Addons{}); err != nil {
		t.Fatal(err)
	}
	first := []byte("before lower speed")
	if _, err := conn.Write(first); err != nil {
		t.Fatal(err)
	}
	if _, err := encoding.DecodeResponseHeader(conn, request); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(first))
	if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, first) {
		t.Fatalf("pre-reduction VPN data failed: %q %v", got, err)
	}
	if _, err := manager.UpdateSubscription(subscriptionrate.Update{
		ID: "account", ExpectedRevision: 1, Revision: 2,
		UplinkBps: 20000, DownlinkBps: 20000,
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := manager.ForEmail("member").WithQuietRateBarrier(ctx, func() ([]byte, error) {
		return []byte("test-only"), nil
	}); err != nil {
		t.Fatalf("reduced live limiter did not quiesce: %v", err)
	}
	next := []byte("same authenticated socket")
	if _, err := conn.Write(next); err != nil {
		t.Fatalf("rate reduction closed VLESS session: %v", err)
	}
	got = make([]byte, len(next))
	if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, next) {
		t.Fatalf("post-reduction VPN data failed: %q %v", got, err)
	}
}
