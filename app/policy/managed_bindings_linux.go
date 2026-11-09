//go:build linux

package policy

import (
	"os"
	"syscall"
)

// The node agent has a different UID. Root/core-owned configuration cannot
// be overwritten by the agent, even if the socket group is shared.
func trustedManagedFileOwner(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && (st.Uid == 0 || st.Uid == uint32(os.Geteuid()))
}
