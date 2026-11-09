//go:build linux

package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
)

func TestManagedBindingsArePerSubscriptionAndProtected(t *testing.T) {
	one, two, executor := uuid.New(), uuid.New(), uuid.New()
	dir := t.TempDir()
	path := filepath.Join(dir, "authority.json")
	input := map[string]rawLeaseBinding{
		"one": {ResourceID: one.String(), ExecutorID: executor.String(), MinAuthorityGeneration: 7},
		"two": {ResourceID: two.String(), ExecutorID: executor.String(), MinAuthorityGeneration: 9},
	}
	encode := func(m map[string]rawLeaseBinding) {
		t.Helper()
		raw, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("ELXRAY_CONTROL_LEASE_BINDINGS_FILE", path)
	subs := map[string]*SubscriptionPolicy{
		"one": {Emails: []string{"first"}, UplinkBps: 1, DownlinkBps: 1},
		"two": {Emails: []string{"second"}, UplinkBps: 1, DownlinkBps: 1},
	}
	encode(input)
	good, err := loadManagedLeaseBindings(subs)
	if err != nil || len(good) != 2 || good["one"].ResourceID != one ||
		good["two"].ResourceID != two || good["one"].ExecutorID != executor ||
		good["two"].MinAuthorityGeneration != 9 {
		t.Fatalf("per-subscription map differs: %+v %v", good, err)
	}
	for name, mutate := range map[string]func(){
		"missing": func() { encode(map[string]rawLeaseBinding{"one": input["one"]}) },
		"duplicate": func() {
			m := map[string]rawLeaseBinding{"one": input["one"], "two": input["two"]}
			x := m["two"]
			x.ResourceID = one.String()
			m["two"] = x
			encode(m)
		},
		"no-generation": func() {
			m := map[string]rawLeaseBinding{"one": input["one"], "two": input["two"]}
			x := m["two"]
			x.MinAuthorityGeneration = 0
			m["two"] = x
			encode(m)
		},
		"bad-executor": func() {
			m := map[string]rawLeaseBinding{"one": input["one"], "two": input["two"]}
			x := m["two"]
			x.ExecutorID = "invalid"
			m["two"] = x
			encode(m)
		},
	} {
		encode(input)
		mutate()
		if _, err := loadManagedLeaseBindings(subs); err == nil {
			t.Fatalf("%s: accepted untrusted binding", name)
		}
	}
	encode(input)
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := loadManagedLeaseBindings(subs); err == nil {
		t.Fatal("world/group-writable binding file authorized")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := loadManagedLeaseBindings(subs); err == nil {
		t.Fatal("world-writable parent allowed managed grants")
	}
}
