package subscriptionrate_test

import (
	"bytes"
	"fmt"
	"io"
	stdnet "net"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/inbound"
	"github.com/xtls/xray-core/proxy/vless/outbound"
	"github.com/xtls/xray-core/testing/servers/tcp"
)

// Two local flows share one server identity. UDP is request/response paced to
// avoid confusing intentional sender flooding/loss with byte-budget enforcement.
func TestSubscriptionMuxAndUDP(t *testing.T) {
	for _, mode := range []string{"tcp-mux", "udp", "udp-mux", "xudp"} {
		for _, direction := range []string{"uplink", "downlink"} {
			t.Run(mode+"/"+direction, func(t *testing.T) {
				network := net.Network_UDP
				if mode == "tcp-mux" {
					network = net.Network_TCP
				}
				var target stdnet.Addr
				if network == net.Network_TCP {
					l, err := stdnet.Listen("tcp", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { l.Close() })
					target = l.Addr()
					go func() {
						for {
							c, err := l.Accept()
							if err != nil {
								return
							}
							go func() { defer c.Close(); c.SetDeadline(time.Now().Add(10 * time.Second)); io.Copy(c, c) }()
						}
					}()
				} else {
					l, err := stdnet.ListenPacket("udp", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { l.Close() })
					target = l.LocalAddr()
					go func() {
						buffer := make([]byte, 65535)
						for {
							n, a, err := l.ReadFrom(buffer)
							if err != nil {
								return
							}
							l.WriteTo(buffer[:n], a)
						}
					}()
				}
				id := uuid.New()
				serverPort, clientPort := tcp.PickPort(), tcp.PickPort()
				if network == net.Network_UDP {
					// PickPort reserves a TCP port in a fixed test range. On
					// Windows, some of those numbers are excluded for UDP;
					// discover an actually bindable ephemeral UDP port.
					probe, err := stdnet.ListenPacket("udp", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					clientPort = net.Port(probe.LocalAddr().(*stdnet.UDPAddr).Port)
					if err := probe.Close(); err != nil {
						t.Fatal(err)
					}
				}
				apps := func() []*serial.TypedMessage {
					return []*serial.TypedMessage{serial.ToTypedMessage(&dispatcher.Config{}), serial.ToTypedMessage(&proxyman.InboundConfig{}), serial.ToTypedMessage(&proxyman.OutboundConfig{})}
				}
				receiver := func(port net.Port) *serial.TypedMessage {
					return serial.ToTypedMessage(&proxyman.ReceiverConfig{Listen: net.NewIPOrDomain(net.LocalHostIP), PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(port)}}})
				}
				budget := &policy.SubscriptionPolicy{Emails: []string{"matrix@example"}}
				const speed = 128 * 1024
				if direction == "uplink" {
					budget.UplinkBps = speed
				} else {
					budget.DownlinkBps = speed
				}
				serverApps := append(apps(), serial.ToTypedMessage(&policy.Config{Subscriptions: map[string]*policy.SubscriptionPolicy{"matrix": budget}}))
				user := func() *protocol.User {
					return &protocol.User{Email: "matrix@example", Account: serial.ToTypedMessage(&vless.Account{Id: id.String()})}
				}
				server, err := core.New(&core.Config{
					App:      serverApps,
					Inbound:  []*core.InboundHandlerConfig{{ReceiverSettings: receiver(serverPort), ProxySettings: serial.ToTypedMessage(&inbound.Config{Users: []*protocol.User{user()}})}},
					Outbound: []*core.OutboundHandlerConfig{{ProxySettings: serial.ToTypedMessage(&freedom.Config{FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}}})}},
				})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { server.Close() })
				if err := server.Start(); err != nil {
					t.Fatal(err)
				}
				dest := net.DestinationFromAddr(target)
				sender := &proxyman.SenderConfig{}
				switch mode {
				case "tcp-mux", "udp-mux":
					sender.MultiplexSettings = &proxyman.MultiplexingConfig{Enabled: true, Concurrency: 4, XudpProxyUDP443: "allow"}
				case "xudp":
					sender.MultiplexSettings = &proxyman.MultiplexingConfig{Enabled: true, Concurrency: -1, XudpConcurrency: 4, XudpProxyUDP443: "allow"}
				}
				client, err := core.New(&core.Config{
					App:      apps(),
					Inbound:  []*core.InboundHandlerConfig{{ReceiverSettings: receiver(clientPort), ProxySettings: serial.ToTypedMessage(&dokodemo.Config{RewriteAddress: net.NewIPOrDomain(dest.Address), RewritePort: uint32(dest.Port), AllowedNetworks: []net.Network{network}})}},
					Outbound: []*core.OutboundHandlerConfig{{ProxySettings: serial.ToTypedMessage(&outbound.Config{Vnext: &protocol.ServerEndpoint{Address: net.NewIPOrDomain(net.LocalHostIP), Port: uint32(serverPort), User: user()}}), SenderSettings: serial.ToTypedMessage(sender)}},
				})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { client.Close() })
				if err := client.Start(); err != nil {
					t.Fatal(err)
				}
				start := time.Now()
				var wg sync.WaitGroup
				for flow := range 2 {
					wg.Go(func() {
						c, err := stdnet.DialTimeout(network.SystemString(), fmt.Sprintf("127.0.0.1:%d", clientPort), time.Second)
						if err != nil {
							t.Error(err)
							return
						}
						defer c.Close()
						c.SetDeadline(time.Now().Add(8 * time.Second))
						for index := range 48 {
							payload := bytes.Repeat([]byte{byte(index + flow)}, 1024)
							if _, err := c.Write(payload); err != nil {
								t.Error(err)
								return
							}
							got := make([]byte, len(payload))
							if network == net.Network_UDP {
								n, err := c.Read(got)
								if err != nil || n != len(payload) {
									t.Errorf("datagram size/error: %d %v", n, err)
									return
								}
							} else {
								if _, err := io.ReadFull(c, got); err != nil {
									t.Error(err)
									return
								}
							}
							if !bytes.Equal(got, payload) {
								t.Error("payload or datagram boundary changed")
								return
							}
						}
					})
				}
				wg.Wait()
				if elapsed := time.Since(start); elapsed < 450*time.Millisecond {
					t.Fatalf("%s bypassed aggregate %s rate: %v", mode, direction, elapsed)
				}
			})
		}
	}
}
