//go:build linux

package elxsecurity

import (
    "context"
    "errors"
    "fmt"
    "net"
    "os"
    "path/filepath"
    "syscall"

    "golang.org/x/sys/unix"
    "google.golang.org/grpc/credentials"
)

type agentCredentials struct {
    uid uint32
    gid uint32
}

// ServerCredentials returns a transport credential verifier for gRPC.
// The Linux kernel, not an RPC field, supplies UID/GID/PID via SO_PEERCRED.
func ServerCredentials(uid, gid uint32) (credentials.TransportCredentials, error) {
    if uid == 0 || gid == 0 {
        return nil, errors.New("managed agent identity must be non-root")
    }
    return &agentCredentials{uid: uid, gid: gid}, nil
}

func (c *agentCredentials) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
    uc, ok := conn.(*net.UnixConn)
    if !ok {
        return nil, nil, errors.New("managed Commander only accepts Unix sockets")
    }
    raw, err := uc.SyscallConn()
    if err != nil { return nil, nil, fmt.Errorf("get managed peer fd: %w", err) }
    var peer *unix.Ucred
    var lookupErr error
    err = raw.Control(func(fd uintptr) {
        peer, lookupErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
    })
    if err != nil || lookupErr != nil || peer == nil {
        return nil, nil, errors.New("cannot authenticate managed Unix peer")
    }
    if peer.Uid != c.uid || peer.Gid != c.gid {
        return nil, nil, errors.New("unauthorized managed agent process identity")
    }
    return conn, UnixPeerInfo{UID:peer.Uid, GID:peer.Gid, PID:peer.Pid}, nil
}
func (*agentCredentials) ClientHandshake(context.Context, string, net.Conn) (net.Conn, credentials.AuthInfo, error) {
    return nil, nil, errors.New("managed Unix credentials are server-only")
}
func (*agentCredentials) Info() credentials.ProtocolInfo {
    return credentials.ProtocolInfo{SecurityProtocol: "elx-unix-peercred", SecurityVersion:"1.0"}
}
func (c *agentCredentials) Clone() credentials.TransportCredentials { return &agentCredentials{uid:c.uid,gid:c.gid} }
func (*agentCredentials) OverrideServerName(string) error { return errors.New("managed Unix credentials are server-only") }

// ListenManaged creates a fresh filesystem socket with explicit agent group
// and without the dangerous net.Listen removal of a pre-existing pathname.
// Parent directory must be owned by the core and unmodifiable by others.
func ListenManaged(path string, gid uint32) (net.Listener, error) {
    if !filepath.IsAbs(path) || path == "/" || len(path) > 100 {
        return nil, errors.New("managed Commander requires an absolute Unix socket pathname")
    }
    parent := filepath.Dir(path)
    info, err := os.Lstat(parent)
    if err != nil { return nil, err }
    st, ok := info.Sys().(*syscall.Stat_t)
    if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
        st.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0o027 != 0 {
        return nil, errors.New("managed socket parent must be owned by core, without group write or any public access")
    }
    if _, err := os.Lstat(path); err == nil {
        return nil, errors.New("managed socket path already exists; refuse to overwrite it")
    } else if !os.IsNotExist(err) { return nil, err }
    listener, err := net.Listen("unix", path)
    if err != nil { return nil, err }
    // A failure to install secure ownership/mode is fatal. The namespace is
    // not exposed until Start has completed this setup.
    if err := os.Chown(path, -1, int(gid)); err != nil {
        listener.Close(); os.Remove(path); return nil, err
    }
    if err := os.Chmod(path, 0o660); err != nil {
        listener.Close(); os.Remove(path); return nil, err
    }
    return listener, nil
}
