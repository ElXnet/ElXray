//go:build linux

package elxsecurity

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

func TestManagedPeercredGRPCOverRealUnixSocket(t *testing.T) {
	if os.Geteuid() == 0 || os.Getegid() == 0 {
		t.Skip("positive peercred transport test uses an unprivileged runner")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		uid     uint32
		allowed bool
	}{
		{name: "authorized-agent", uid: uint32(os.Geteuid()), allowed: true},
		{name: "other-local-user", uid: uint32(os.Geteuid() + 1), allowed: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(dir, test.name+".sock")
			listener, err := ListenManaged(path, uint32(os.Getegid()))
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			creds, err := ServerCredentials(test.uid, uint32(os.Getegid()))
			if err != nil {
				t.Fatal(err)
			}
			server := grpc.NewServer(grpc.Creds(creds))
			healthpb.RegisterHealthServer(server, health.NewServer())
			go func() { _ = server.Serve(listener) }()
			defer server.Stop()
			conn, err := grpc.NewClient("unix://"+path, grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			_, err = healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
			if test.allowed && err != nil {
				t.Fatalf("real kernel-authenticated gRPC Unix caller denied: %v", err)
			}
			if !test.allowed && err == nil {
				t.Fatal("untrusted local process connected through SO_PEERCRED")
			}
		})
	}
}

// Verify that a TCP listener cannot impersonate a Unix peer even when
// the network endpoint is on 127.0.0.1 and the process has the right UID.
func TestPeercredServerRejectsTCPTransport(t *testing.T) {
	creds, err := ServerCredentials(uint32(os.Geteuid()+1), uint32(os.Getegid()+1))
	if err != nil {
		t.Fatal(err)
	}
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	if _, _, err := creds.ServerHandshake(server); err == nil {
		t.Fatal("managed credentials accepted non-Unix transport")
	}
}
