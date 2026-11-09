//go:build linux

// elx-stage3-migrate is an OFFLINE, explicit, fail-closed migration from a
// nonempty v1 managed policy snapshot to the v2 store/journal pair.
// It does not approve or create the independent PostgreSQL Control witness.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common/elxjournal"
	"golang.org/x/sys/unix"
)

type binding struct {
	ResourceID             string `json:"resourceId"`
	ExecutorID             string `json:"executorId"`
	MinAuthorityGeneration uint64 `json:"minAuthorityGeneration"`
}
type policy struct {
	ID       string
	Revision uint64
	Emails   []string
}

func readPrivate(path string) ([]byte, error) {
	info, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > 16<<20 {
		return nil, errors.New("migration input must be a private regular file under 16 MiB")
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 16<<20+1))
}

func run(args []string) error {
	fs := flag.NewFlagSet("elx-stage3-migrate", flag.ContinueOnError)
	path := fs.String("state", "", "ABSOLUTE path to stopped core policy snapshot")
	journalPath := fs.String("journal", "", "ABSOLUTE path to new store ledger")
	bindingsPath := fs.String("bindings", "", "protected trusted authority binding file")
	store := fs.String("store", "", "Control-registered immutable store UUID")
	sha := fs.String("expected-sha256", "", "SHA-256 of independently approved v1 state file")
	approve := fs.String("approve", "", "exact OFFLINE_CONTROL_APPROVED")
	if e := fs.Parse(args); e != nil {
		return e
	}
	if fs.NArg() != 0 || *approve != "OFFLINE_CONTROL_APPROVED" ||
		!filepath.IsAbs(*path) || !filepath.IsAbs(*journalPath) || !filepath.IsAbs(*bindingsPath) ||
		*path == *journalPath || *path == *bindingsPath || *journalPath == *bindingsPath {
		return errors.New("explicit offline Control approval and absolute, distinct paths required")
	}
	storeID, e := uuid.Parse(*store)
	if e != nil || storeID == uuid.Nil || storeID.String() != *store {
		return errors.New("canonical immutable store UUID required")
	}
	if len(*sha) != 64 || strings.ToLower(*sha) != *sha {
		return errors.New("expected SHA-256 of signed-off original v1 snapshot required")
	}
	// Only the stopped core can be migrated. An open core .lock must abort.
	lock, e := os.OpenFile(*path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if e != nil {
		return e
	}
	defer lock.Close()
	if e = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return errors.New("ElXray policy core is still running or locked")
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	raw, e := readPrivate(*path)
	if e != nil {
		return e
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != *sha {
		return errors.New("policy snapshot SHA-256 differs from operator-approved baseline")
	}
	var obj map[string]json.RawMessage
	if e = json.Unmarshal(raw, &obj); e != nil {
		return e
	}
	var version int
	if json.Unmarshal(obj["Version"], &version) != nil || version != 1 || obj["StoreID"] != nil {
		return errors.New("only an existing version-1 managed snapshot may be migrated")
	}
	var current, base map[string]policy
	if json.Unmarshal(obj["Current"], &current) != nil || json.Unmarshal(obj["Base"], &base) != nil ||
		len(current) == 0 || len(base) != len(current) {
		return errors.New("managed v1 snapshot must contain nonempty current and base policies")
	}
	protectedBindings, e := readPrivate(*bindingsPath)
	if e != nil {
		return e
	}
	var bindings map[string]binding
	if json.Unmarshal(protectedBindings, &bindings) != nil || len(bindings) != len(current) {
		return errors.New("trusted managed subscription bindings do not match saved policy set")
	}
	names := make([]string, 0, len(current))
	for id, p := range current {
		b, ok := bindings[id]
		resource, e := uuid.Parse(b.ResourceID)
		executor, e2 := uuid.Parse(b.ExecutorID)
		if !ok || e != nil || e2 != nil || resource == uuid.Nil || executor == uuid.Nil ||
			resource.String() != b.ResourceID || executor.String() != b.ExecutorID ||
			b.MinAuthorityGeneration == 0 || p.Revision == 0 || p.ID != id || len(p.Emails) == 0 {
			return fmt.Errorf("untrusted policy/binding baseline %q", id)
		}
		if _, ok := base[id]; !ok {
			return fmt.Errorf("base subscription %q missing", id)
		}
		names = append(names, id)
	}
	sort.Strings(names)
	var denies []string
	if r := obj["DeniedProfiles"]; len(r) > 0 && string(r) != "null" {
		var saved []string
		if json.Unmarshal(r, &saved) != nil {
			return errors.New("invalid v1 denied profiles")
		}
		seen := map[string]bool{}
		for _, encoded := range saved {
			binary, e := hex.DecodeString(encoded)
			if e != nil || len(binary) != 16 || encoded != strings.ToLower(encoded) {
				return errors.New("malformed v1 VLESS deny tombstone")
			}
			id, e := uuid.FromBytes(binary)
			if e != nil || id == uuid.Nil || seen[id.String()] {
				return errors.New("duplicate or zero VLESS deny tombstone")
			}
			seen[id.String()] = true
			denies = append(denies, id.String())
		}
	}
	// Create a write-once, fsynced independent backup before any mutations.
	backup := *path + ".stage3-v1.backup"
	f, e := os.OpenFile(backup, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if e != nil {
		return fmt.Errorf("backup already exists/unsafe migration retry: %w", e)
	}
	if _, e = f.Write(raw); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	backupDir, e := os.Open(filepath.Dir(backup))
	if e != nil {
		return e
	}
	if e = backupDir.Sync(); e != nil {
		backupDir.Close()
		return e
	}
	if e = backupDir.Close(); e != nil {
		return e
	}
	if e = elxjournal.Provision(*journalPath, *store); e != nil {
		return e
	}
	j, e := elxjournal.Open(*journalPath)
	if e != nil {
		return e
	}
	for _, id := range names {
		b := bindings[id]
		if e = j.BootstrapResource(b.ResourceID, current[id].Revision, b.MinAuthorityGeneration); e != nil {
			return e
		}
	}
	if e = j.BootstrapDeniedProfiles(denies); e != nil {
		return e
	}
	obj["Version"] = json.RawMessage("2")
	encodedStore, _ := json.Marshal(*store)
	obj["StoreID"] = encodedStore
	migrated, e := json.Marshal(obj)
	if e != nil {
		return e
	}
	// Preserve owner/group of the original core-owned state before rename.
	st, e := os.Stat(*path)
	if e != nil {
		return e
	}
	dir := filepath.Dir(*path)
	temp, e := os.CreateTemp(dir, ".elx-v2-migrate-*")
	if e != nil {
		return e
	}
	defer os.Remove(temp.Name())
	if e = temp.Chmod(0o600); e != nil {
		temp.Close()
		return e
	}
	if stat, ok := st.Sys().(*syscall.Stat_t); ok {
		if e = os.Chown(temp.Name(), int(stat.Uid), int(stat.Gid)); e != nil {
			temp.Close()
			return e
		}
	}
	if _, e = temp.Write(migrated); e != nil {
		temp.Close()
		return e
	}
	if e = temp.Sync(); e != nil {
		temp.Close()
		return e
	}
	if e = temp.Close(); e != nil {
		return e
	}
	if e = os.Rename(temp.Name(), *path); e != nil {
		return e
	}
	parent, e := os.Open(dir)
	if e != nil {
		return e
	}
	defer parent.Close()
	if e = parent.Sync(); e != nil {
		return e
	}
	fmt.Printf("v2 core snapshot migrated; Control witness MUST be independently approved: store=%s policies=%d denied=%d\n", *store, len(names), len(denies))
	return nil
}

func main() {
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
