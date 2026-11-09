//go:build linux

package elxsecurity

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestLinuxPeerCredentialsRejectForeignLocalIdentity(t *testing.T) {
	if os.Geteuid() == 0 || os.Getegid() == 0 {
		t.Skip("test requires a non-root runner")
	}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "agent.sock")
	listener, err := ListenManaged(path, uint32(os.Getegid()))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if _, err := ListenManaged(path, uint32(os.Getegid())); err == nil {
		t.Fatal("managed socket replaced a pre-existing file")
	}
	mode, err := os.Stat(path)
	if err != nil || mode.Mode().Perm() != 0o660 {
		t.Fatalf("insecure socket mode: %v %v", mode, err)
	}
	client, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	creds, err := ServerCredentials(uint32(os.Geteuid()), uint32(os.Getegid()))
	if err != nil {
		t.Fatal(err)
	}
	_, auth, err := creds.ServerHandshake(accepted)
	if err != nil {
		t.Fatal(err)
	}
	ident, ok := auth.(UnixPeerInfo)
	if !ok || ident.UID != uint32(os.Geteuid()) || ident.GID != uint32(os.Getegid()) || ident.PID <= 0 {
		t.Fatalf("kernel peer mismatch: %+v", auth)
	}
	other, err := ServerCredentials(uint32(os.Geteuid()+1), uint32(os.Getegid()))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := other.ServerHandshake(accepted); err == nil {
		t.Fatal("foreign local user authenticated")
	}
}
