package policy

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"reflect"

	"github.com/xtls/xray-core/common/subscriptionrate"
)

type savedPolicies struct {
	Version int
	Base    map[string]subscriptionrate.Policy
	Current map[string]subscriptionrate.Policy
}

type policyStore struct {
	path   string
	lock   *os.File
	key    ed25519.PrivateKey
	base   map[string]subscriptionrate.Policy
	failed bool
}

// A provisioned empty manifest is exactly {"Version":1}. Missing or damaged
// files are never treated as a fresh state directory.
func (m *Instance) restorePolicies(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("policy state path must be absolute")
	}
	lock, err := lockPolicyFile(path + ".lock")
	if err != nil {
		return err
	}
	store := &policyStore{path: path, lock: lock, base: maps.Clone(m.subscriptionPolicies)}
	defer func() {
		if m.store == nil {
			lock.Close()
		}
	}()
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	const maxSize = 16 << 20
	data, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil {
		return err
	}
	var saved savedPolicies
	if len(data) > maxSize || json.Unmarshal(data, &saved) != nil || saved.Version != 1 {
		return errors.New("invalid persisted policy state")
	}
	if saved.Base == nil && saved.Current == nil && string(data) != `{"Version":1}` {
		return errors.New("invalid uninitialized policy state")
	}
	key, err := os.ReadFile(path + ".key")
	if err != nil {
		return err
	}
	seed, err := hex.DecodeString(string(key))
	if err != nil || len(seed) != ed25519.SeedSize {
		return errors.New("invalid policy signing seed")
	}
	store.key = ed25519.NewKeyFromSeed(seed)
	if saved.Base == nil && saved.Current == nil {
		if err := store.write(m.subscriptionPolicies); err != nil {
			return err
		}
	} else {
		if !reflect.DeepEqual(saved.Base, store.base) || len(saved.Current) != len(store.base) {
			return errors.New("persisted policy state does not match startup bindings")
		}
		for id, p := range saved.Current {
			base, ok := store.base[id]
			if !ok || p.ID != id || !reflect.DeepEqual(base.Emails, p.Emails) || p.Revision < base.Revision ||
				p.UplinkBps > subscriptionrate.MaxRate || p.DownlinkBps > subscriptionrate.MaxRate ||
				(p.Revision == base.Revision && !reflect.DeepEqual(p, base)) ||
				(p.Revision > base.Revision && (p.UplinkBps == 0 || p.DownlinkBps == 0)) {
				return errors.New("invalid recovered subscription policy")
			}
			m.subscriptionPolicies[id] = p
		}
	}
	m.store = store
	return nil
}

func (s *policyStore) write(current map[string]subscriptionrate.Policy) error {
	dir := filepath.Dir(s.path)
	f, err := os.CreateTemp(dir, ".elx-policy-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err := json.NewEncoder(f).Encode(savedPolicies{1, s.base, current}); err != nil {
		return err
	}
	if info, err := f.Stat(); err != nil {
		return err
	} else if info.Size() > 16<<20 {
		return errors.New("persisted policy state exceeds size limit")
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), s.path); err != nil {
		return err
	}
	parent, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}

// DurablePolicyProof signs the exact live policy only after persistence has
// succeeded. The challenge binds the proof to a Control operation.
func (m *Instance) DurablePolicyProof(p subscriptionrate.Policy, challenge string) ([]byte, error) {
	m.subscriptionMu.Lock()
	defer m.subscriptionMu.Unlock()
	current, ok := m.subscriptionPolicies[p.ID]
	if m.store == nil || m.store.failed || !ok || !reflect.DeepEqual(current, p) {
		return nil, errors.New("durable policy unavailable")
	}
	message := fmt.Appendf(nil, "elx-policy-v1\n%x\n%x\n%d\n%d\n%d\n%t", challenge, p.ID, p.Revision, p.UplinkBps, p.DownlinkBps, p.Disabled)
	return ed25519.Sign(m.store.key, message), nil
}
