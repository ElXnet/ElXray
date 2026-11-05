package command

import (
	"context"
	"net"
	"testing"
	"time"

	apppolicy "github.com/xtls/xray-core/app/policy"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func TestRejectNonLocalManagement(t *testing.T) {
	for _, addr := range []net.Addr{&net.TCPAddr{IP: net.ParseIP("192.168.1.2")}, &net.TCPAddr{IP: net.ParseIP("8.8.8.8")}, nil} {
		if status.Code(checkLocalPeer(peer.NewContext(context.Background(), &peer.Peer{Addr: addr}))) != codes.PermissionDenied {
			t.Fatal("remote peer allowed", addr)
		}
	}
	if status.Code(checkLocalPeer(context.Background())) != codes.PermissionDenied {
		t.Fatal("missing peer allowed")
	}
	for _, addr := range []net.Addr{&net.TCPAddr{IP: net.ParseIP("127.0.0.1")}, &net.TCPAddr{IP: net.ParseIP("::1")}, &net.UnixAddr{Name: "/private/socket"}} {
		if err := checkLocalPeer(peer.NewContext(context.Background(), &peer.Peer{Addr: addr})); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSubscriptionRPC(t *testing.T) {
	m, err := apppolicy.New(context.Background(), &apppolicy.Config{Subscriptions: map[string]*apppolicy.SubscriptionPolicy{"a": {Emails: []string{"email"}}}})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	(&service{manager: m}).Register(server)
	go server.Serve(listener)
	t.Cleanup(server.Stop)
	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client := NewSubscriptionServiceClient(conn)
	p, err := client.GetSubscription(ctx, &GetSubscriptionRequest{Id: "a"})
	if err != nil || p.Revision != 1 {
		t.Fatal(p, err)
	}
	update := &SetSubscriptionRequest{Id: "a", ExpectedRevision: 1, Revision: 2, UplinkBps: proto.Uint64(123), DownlinkBps: proto.Uint64(456), Disabled: proto.Bool(false)}
	for range 2 {
		p, err = client.SetSubscription(ctx, update)
		if err != nil || p.Revision != 2 || p.DownlinkBps != 456 {
			t.Fatal(p, err)
		}
	}
	for _, rates := range [][2]uint64{{0, 456}, {123, 0}, {0, 0}} {
		for _, disabled := range []bool{false, true} {
			_, err := client.SetSubscription(ctx, &SetSubscriptionRequest{
				Id: "a", ExpectedRevision: 2, Revision: 3,
				UplinkBps: proto.Uint64(rates[0]), DownlinkBps: proto.Uint64(rates[1]),
				Disabled: proto.Bool(disabled),
			})
			if status.Code(err) != codes.PermissionDenied {
				t.Fatalf("zero-rate update returned %v", err)
			}
		}
	}
	p, err = client.GetSubscription(ctx, &GetSubscriptionRequest{Id: "a"})
	if err != nil || p.GetRevision() != 2 || p.GetUplinkBps() != 123 || p.GetDownlinkBps() != 456 {
		t.Fatalf("rejected update changed the policy: %v, %v", p, err)
	}
	*update.UplinkBps++
	if _, err = client.SetSubscription(ctx, update); status.Code(err) != codes.Aborted {
		t.Fatal("stale update", err)
	}
	if _, err := client.SetSubscription(ctx, &SetSubscriptionRequest{Id: "a", ExpectedRevision: 2, Revision: 3}); status.Code(err) != codes.InvalidArgument {
		t.Fatal("omitted policy fields accepted", err)
	}
	update.ExpectedRevision = 0
	if _, err = client.SetSubscription(ctx, update); status.Code(err) != codes.InvalidArgument {
		t.Fatal("invalid update", err)
	}
	if _, err = client.GetSubscription(ctx, &GetSubscriptionRequest{Id: "missing"}); status.Code(err) != codes.NotFound {
		t.Fatal(err)
	}
}
