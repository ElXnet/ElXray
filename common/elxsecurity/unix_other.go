//go:build !linux

package elxsecurity

import (
    "errors"
    "net"

    "google.golang.org/grpc/credentials"
)

// A managed instance requires kernel-verified peer credentials; fail closed
// instead of accepting loopback or a Unix address on unsupported platforms.
func ServerCredentials(uint32, uint32) (credentials.TransportCredentials, error) {
    return nil, errors.New("managed Commander peer authentication requires Linux")
}
func ListenManaged(string, uint32) (net.Listener, error) {
    return nil, errors.New("managed Commander Unix socket requires Linux")
}
