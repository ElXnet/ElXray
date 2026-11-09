package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

// leaseBinding is a pinned per-subscription authority identity. The resource
// and executor are NOT taken from client-provided headers or live lease JSON.
type leaseBinding struct {
	ResourceID             uuid.UUID
	ExecutorID             uuid.UUID
	MinAuthorityGeneration uint64
}

type rawLeaseBinding struct {
	ResourceID             string `json:"resourceId"`
	ExecutorID             string `json:"executorId"`
	MinAuthorityGeneration uint64 `json:"minAuthorityGeneration"`
}

func loadManagedLeaseBindings(subs map[string]*SubscriptionPolicy) (map[string]leaseBinding, error) {
	path := os.Getenv("ELXRAY_CONTROL_LEASE_BINDINGS_FILE")
	if !filepath.IsAbs(path) || path == "/" {
		return nil, errors.New("managed core requires absolute trusted lease bindings file")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("managed lease bindings inaccessible: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Size() > 1<<20 ||
		!trustedManagedFileOwner(info) {
		return nil, errors.New("managed lease bindings file must be regular, protected and root/core owned")
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0o022 != 0 ||
		!trustedManagedFileOwner(parent) {
		return nil, errors.New("managed lease bindings directory must be root/core owned and not writable by agents")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if err != nil || len(raw) > 1<<20 {
		return nil, errors.New("managed lease bindings file unreadable or exceeds 1 MiB")
	}
	var input map[string]rawLeaseBinding
	if err := json.Unmarshal(raw, &input); err != nil || len(input) != len(subs) || len(input) == 0 {
		return nil, errors.New("managed lease bindings do not cover every configured subscription")
	}
	out := make(map[string]leaseBinding, len(subs))
	resources := make(map[uuid.UUID]bool)
	for id := range subs {
		rawBinding, ok := input[id]
		if !ok || id == "" || strings.TrimSpace(id) != id {
			return nil, errors.New("unbound managed subscription")
		}
		resource, errR := uuid.Parse(rawBinding.ResourceID)
		executor, errE := uuid.Parse(rawBinding.ExecutorID)
		if errR != nil || errE != nil || resource == uuid.Nil || executor == uuid.Nil ||
			resource.String() != rawBinding.ResourceID || executor.String() != rawBinding.ExecutorID ||
			rawBinding.MinAuthorityGeneration == 0 ||
			rawBinding.MinAuthorityGeneration > uint64(^uint64(0)>>1) || resources[resource] {
			return nil, errors.New("invalid or duplicate managed lease resource/executor/authority identity")
		}
		resources[resource] = true
		out[id] = leaseBinding{
			ResourceID: resource, ExecutorID: executor,
			MinAuthorityGeneration: rawBinding.MinAuthorityGeneration,
		}
	}
	return out, nil
}
