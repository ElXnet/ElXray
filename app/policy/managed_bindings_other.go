//go:build !linux

package policy

import "os"

// No Linux SO_PEERCRED here, and never accept an untrusted managed manifest.
func trustedManagedFileOwner(os.FileInfo) bool { return false }
