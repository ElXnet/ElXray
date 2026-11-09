// Package elxsecurity binds the managed Commander API to a dedicated
// Linux Unix-domain agent identity. A loopback address is not a credential.
package elxsecurity

import (
    "errors"
    "os"
    "strconv"
)

func Managed() bool { return os.Getenv("ELXRAY_MODE") == "managed" }

// AgentIdentity is a dedicated, non-root OS UID/GID. It must never be the
// identity of the ElXray process: compromising an unrelated local account
// must not grant access to the rate or lease administration surface.
func AgentIdentity() (uint32, uint32, error) {
    uid, err := strconv.ParseUint(os.Getenv("ELXRAY_AGENT_UID"), 10, 32)
    if err != nil || uid == 0 || uint64(os.Geteuid()) == uid {
        return 0, 0, errors.New("managed agent requires a distinct non-root UID")
    }
    gid, err := strconv.ParseUint(os.Getenv("ELXRAY_AGENT_GID"), 10, 32)
    if err != nil || gid == 0 {
        return 0, 0, errors.New("managed agent requires an explicit non-root GID")
    }
    return uint32(uid), uint32(gid), nil
}

// UnixPeerInfo is set by gRPC's Linux SO_PEERCRED-backed transport only.
// Request metadata and a net.UnixAddr never establish this identity.
type UnixPeerInfo struct {
    UID uint32
    GID uint32
    PID int32
}
func (UnixPeerInfo) AuthType() string { return "elx-unix-peercred-v1" }
