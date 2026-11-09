// Package elxjournal implements a fail-closed, durable managed-operation ledger.
// Control remains the source of grants. The policy manager holds the exclusive
// process lock for the full lifetime of a Journal.
package elxjournal

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sync"
	"time"
)

var (
	ErrUncertain = errors.New("previous operation outcome unknown; reconcile first")
	ErrCollision = errors.New("operation ID reused with different payload")
	ErrStale     = errors.New("stale revision or authority generation")
	ErrCorrupt   = errors.New("journal damaged or inconsistent; Control reconciliation required")
	ErrInvalid   = errors.New("invalid managed operation")
)

const (
	formatVersion = 2
	maxBytes      = 16 << 20
)

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type Command struct {
	OperationID         string `json:"operationId"`
	NodeID              string `json:"nodeId"`
	ExecutorID          string `json:"executorId"`
	ResourceID          string `json:"resourceId"`
	AuthorityGeneration uint64 `json:"authorityGeneration"`
	ExpectedRevision    uint64 `json:"expectedRevision"`
	NewRevision         uint64 `json:"newRevision"`
	PayloadSHA256       string `json:"payloadSha256"`
	Kind                string `json:"kind"`
}
type Receipt struct {
	Command
	State              string `json:"state"`
	CompletedUnixNanos int64  `json:"completedUnixNanos,omitempty"`
}

// LeaseWatermark is the maximum accepted signed authority and monotonic
// Control sequence for one locally pinned resource. The caller MUST verify the
// lease signature and node/executor/resource binding before recording it.
type LeaseWatermark struct {
	AuthorityGeneration uint64 `json:"authorityGeneration"`
	Sequence            int64  `json:"sequence"`
	NotAfterUnix        int64  `json:"notAfterUnix"`
}

type image struct {
	Version        int                       `json:"version"`
	StoreID        string                    `json:"storeId"`
	Sequence       uint64                    `json:"sequence"`
	Operations     map[string]Receipt        `json:"operations"`
	Revisions      map[string]uint64         `json:"revisions"`
	Generations    map[string]uint64         `json:"generations"`
	Leases         map[string]LeaseWatermark `json:"leases"`
	DeniedProfiles map[string]uint64         `json:"deniedProfiles"`
}
type anchor struct {
	Version     int    `json:"version"`
	StoreID     string `json:"storeId"`
	Sequence    uint64 `json:"sequence"`
	ImageSHA256 string `json:"imageSha256"`
}
type Journal struct {
	mu     sync.Mutex
	path   string
	img    image
	failed bool
	hook   func(string) error // unexported crash-injection hook, tests only
}

func validPath(path string) bool { return filepath.IsAbs(path) && path != string(filepath.Separator) }

func validCommand(c Command) bool {
	for _, id := range []string{c.OperationID, c.NodeID, c.ExecutorID, c.ResourceID} {
		if !uuidRE.MatchString(id) || id == "00000000-0000-0000-0000-000000000000" {
			return false
		}
	}
	if c.AuthorityGeneration == 0 || c.NewRevision == 0 || c.NewRevision != c.ExpectedRevision+1 ||
		c.NewRevision <= c.ExpectedRevision || len(c.PayloadSHA256) != 64 || len(c.Kind) == 0 || len(c.Kind) > 64 {
		return false
	}
	raw, e := hex.DecodeString(c.PayloadSHA256)
	return e == nil && hex.EncodeToString(raw) == c.PayloadSHA256
}

func protectedRead(path string) ([]byte, error) {
	st, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !st.Mode().IsRegular() || st.Size() > maxBytes || (runtime.GOOS != "windows" && st.Mode().Perm()&0o077 != 0) {
		return nil, ErrCorrupt
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	data, e := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if e != nil || len(data) > maxBytes {
		return nil, ErrCorrupt
	}
	return data, nil
}

func snapshot(s image) image {
	s.Operations = maps.Clone(s.Operations)
	s.Revisions = maps.Clone(s.Revisions)
	s.Generations = maps.Clone(s.Generations)
	s.Leases = maps.Clone(s.Leases)
	s.DeniedProfiles = maps.Clone(s.DeniedProfiles)
	return s
}

// Provision is an explicit one-time deployment operation, never an automatic
// recovery fallback. Failure midway requires reconciliation, not re-creation.
func Provision(path, storeID string) error {
	if !validPath(path) || !uuidRE.MatchString(storeID) {
		return ErrInvalid
	}
	for _, name := range []string{path, path + ".anchor"} {
		_, e := os.Lstat(name)
		if e == nil {
			return ErrCorrupt
		}
		if !os.IsNotExist(e) {
			return e
		}
	}
	j := &Journal{path: path}
	return j.persist(image{Version: formatVersion, StoreID: storeID, Operations: map[string]Receipt{}, Revisions: map[string]uint64{}, Generations: map[string]uint64{}, Leases: map[string]LeaseWatermark{}, DeniedProfiles: map[string]uint64{}})
}

// Open fails on a missing anchor, incomplete commit, altered file or single
// snapshot rollback. Coordinated rollback of both files requires a REMOTE
// monotonic Control watermark: local hashes cannot prevent that attack.
func Open(path string) (*Journal, error) {
	if !validPath(path) {
		return nil, ErrInvalid
	}
	data, e := protectedRead(path)
	if e != nil {
		return nil, fmt.Errorf("journal image: %w", e)
	}
	stamp, e := protectedRead(path + ".anchor")
	if e != nil {
		return nil, fmt.Errorf("journal anchor: %w", e)
	}
	var s image
	var a anchor
	if json.Unmarshal(data, &s) != nil || json.Unmarshal(stamp, &a) != nil ||
		s.Version != formatVersion || a.Version != formatVersion || s.StoreID != a.StoreID ||
		!uuidRE.MatchString(s.StoreID) || s.Sequence != a.Sequence || s.Operations == nil ||
		s.Revisions == nil || s.Generations == nil || s.Leases == nil || s.DeniedProfiles == nil {
		return nil, ErrCorrupt
	}
	sum := sha256.Sum256(data)
	if a.ImageSHA256 != hex.EncodeToString(sum[:]) {
		return nil, ErrCorrupt
	}
	for resource, w := range s.Leases {
		if !uuidRE.MatchString(resource) || w.AuthorityGeneration == 0 || w.Sequence <= 0 || w.NotAfterUnix <= 0 ||
			w.AuthorityGeneration < s.Generations[resource] {
			return nil, ErrCorrupt
		}
	}
	for profile, gen := range s.DeniedProfiles {
		if !uuidRE.MatchString(profile) || gen == 0 {
			return nil, ErrCorrupt
		}
	}
	for id, r := range s.Operations {
		if id != r.OperationID || !validCommand(r.Command) || (r.State != "INTENT" && r.State != "APPLIED") {
			return nil, ErrCorrupt
		}
	}
	return &Journal{path: path, img: s}, nil
}

// BootstrapDeniedProfiles preserves old permanent profile denials before
// converting an operator-approved v1 snapshot to the journal-managed v2.
// It is only permitted before any leases or real operations exist.
func (j *Journal) BootstrapDeniedProfiles(profiles []string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.failed {
		return ErrCorrupt
	}
	if len(j.img.Operations) > 0 || len(j.img.Leases) > 0 {
		return ErrUncertain
	}
	next := snapshot(j.img)
	for _, profile := range profiles {
		if !uuidRE.MatchString(profile) {
			return ErrInvalid
		}
		if next.DeniedProfiles[profile] != 0 {
			return ErrCollision
		}
		next.DeniedProfiles[profile] = 1
	}
	if e := j.persist(next); e != nil {
		j.failed = true
		return e
	}
	j.img = next
	return nil
}

// DeniedProfiles is the durable non-revocable tombstone set. A restored
// snapshot missing any tombstone MUST fail closed before managed admission.
func (j *Journal) DeniedProfiles() map[string]uint64 {
	j.mu.Lock()
	defer j.mu.Unlock()
	return maps.Clone(j.img.DeniedProfiles)
}

func (j *Journal) RecordDeniedProfile(profile string, generation uint64) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.failed {
		return ErrCorrupt
	}
	if !uuidRE.MatchString(profile) || generation == 0 {
		return ErrInvalid
	}
	old := j.img.DeniedProfiles[profile]
	if old > generation {
		return ErrStale
	}
	if old == generation {
		return nil
	}
	next := snapshot(j.img)
	next.DeniedProfiles[profile] = generation
	if e := j.persist(next); e != nil {
		j.failed = true
		return e
	}
	j.img = next
	return nil
}

// HasPending returns true if any previously recorded mutation could have
// reached the live data plane without a completed durable receipt. Re-admit
// nothing until Control reconciles it.
func (j *Journal) HasPending() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.failed {
		return true
	}
	for _, r := range j.img.Operations {
		if r.State == "INTENT" {
			return true
		}
	}
	return false
}

// RecordVerifiedLease persistently advances the anti-replay HWM before the
// limiter accepts a new Control-signed lease. A torn write marks the journal
// failed and caller must deny all affected traffic. This is a LOCAL HWM only;
// coordinated image+anchor rollback needs an independent Control witness.
func (j *Journal) RecordVerifiedLease(resource string, generation uint64, sequence, notAfter int64) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.failed {
		return ErrCorrupt
	}
	if !uuidRE.MatchString(resource) || generation == 0 || sequence <= 0 || notAfter <= 0 {
		return ErrInvalid
	}
	if j.HasPendingLocked(resource) {
		return ErrUncertain
	}
	current := j.img.Leases[resource]
	if generation < current.AuthorityGeneration || generation < j.img.Generations[resource] ||
		sequence <= current.Sequence || (current.Sequence > 0 && notAfter < current.NotAfterUnix && generation == current.AuthorityGeneration) {
		return ErrStale
	}
	next := snapshot(j.img)
	next.Leases[resource] = LeaseWatermark{AuthorityGeneration: generation, Sequence: sequence, NotAfterUnix: notAfter}
	if e := j.persist(next); e != nil {
		j.failed = true
		return e
	}
	j.img = next
	return nil
}

func (j *Journal) HasPendingLocked(resource string) bool {
	for _, r := range j.img.Operations {
		if r.ResourceID == resource && r.State == "INTENT" {
			return true
		}
	}
	return false
}

func (j *Journal) Lease(resource string) (LeaseWatermark, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	v, ok := j.img.Leases[resource]
	return v, ok
}

// BootstrapResource is an EXPLICIT, OFFLINE migration step. An agent must
// reconcile the baseline revision and epoch with Control before invoking it;
// the core NEVER silently seeds a missing resource during normal startup.
// A previously initialized resource or a journal with operations cannot be
// rolled back to an older policy through this helper.
func (j *Journal) BootstrapResource(resource string, revision, generation uint64) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.failed {
		return ErrCorrupt
	}
	if !uuidRE.MatchString(resource) || revision == 0 || generation == 0 {
		return ErrInvalid
	}
	if _, ok := j.img.Revisions[resource]; ok {
		return ErrCollision
	}
	if _, ok := j.img.Generations[resource]; ok {
		return ErrCollision
	}
	if len(j.img.Operations) != 0 || len(j.img.Leases) != 0 {
		return ErrUncertain
	}
	next := snapshot(j.img)
	next.Revisions[resource] = revision
	next.Generations[resource] = generation
	if e := j.persist(next); e != nil {
		j.failed = true
		return e
	}
	j.img = next
	return nil
}

// StoreID is minted only by explicit provision and remains stable across
// core incarnations; it is included in every signed applied-op receipt.
func (j *Journal) StoreID() string {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.img.StoreID
}

// ResourceState is a read-only local high-water view. The caller must compare
// it against the independently trusted Control grant before admitting traffic.
func (j *Journal) ResourceState(resource string) (revision, generation uint64, ok bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	revision, ok = j.img.Revisions[resource]
	generation = j.img.Generations[resource]
	return
}

func (j *Journal) Get(id string) (Receipt, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	r, ok := j.img.Operations[id]
	return r, ok
}

// Begin durably records INTENT *before* any live change. Duplicate IDs must
// match every signed identity and payload field, not just the hash.
func (j *Journal) Begin(c Command) (Receipt, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.failed {
		return Receipt{}, ErrCorrupt
	}
	if !validCommand(c) {
		return Receipt{}, ErrInvalid
	}
	if r, ok := j.img.Operations[c.OperationID]; ok {
		if r.Command != c {
			return Receipt{}, ErrCollision
		}
		return r, nil
	}
	if j.img.Revisions[c.ResourceID] != c.ExpectedRevision || c.AuthorityGeneration < j.img.Generations[c.ResourceID] || (j.img.Leases[c.ResourceID].AuthorityGeneration > 0 && c.AuthorityGeneration < j.img.Leases[c.ResourceID].AuthorityGeneration) {
		return Receipt{}, ErrStale
	}
	for _, r := range j.img.Operations {
		if r.ResourceID == c.ResourceID && r.State == "INTENT" {
			return Receipt{}, ErrUncertain
		}
	}
	next := snapshot(j.img)
	r := Receipt{Command: c, State: "INTENT"}
	next.Operations[c.OperationID] = r
	if e := j.persist(next); e != nil {
		j.failed = true
		return Receipt{}, e
	}
	j.img = next
	return r, nil
}

// MarkApplied must follow authenticated live core readback. A failed storage
// transition leaves the result UNKNOWN; the caller MUST NOT free allocations.
func (j *Journal) MarkApplied(id string) (Receipt, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.failed {
		return Receipt{}, ErrCorrupt
	}
	r, ok := j.img.Operations[id]
	if !ok {
		return Receipt{}, ErrInvalid
	}
	if r.State == "APPLIED" {
		return r, nil
	}
	if r.State != "INTENT" || j.img.Revisions[r.ResourceID] != r.ExpectedRevision ||
		r.AuthorityGeneration < j.img.Generations[r.ResourceID] {
		return Receipt{}, ErrStale
	}
	next := snapshot(j.img)
	r.State = "APPLIED"
	r.CompletedUnixNanos = time.Now().UTC().UnixNano()
	next.Operations[id] = r
	next.Revisions[r.ResourceID] = r.NewRevision
	next.Generations[r.ResourceID] = r.AuthorityGeneration
	if e := j.persist(next); e != nil {
		j.failed = true
		return Receipt{}, e
	}
	j.img = next
	return r, nil
}

func (j *Journal) persist(next image) error {
	next.Sequence++
	data, e := json.Marshal(next)
	if e != nil {
		return e
	}
	if len(data) > maxBytes {
		return ErrInvalid
	}
	h := sha256.Sum256(data)
	proof, e := json.Marshal(anchor{Version: formatVersion, StoreID: next.StoreID, Sequence: next.Sequence, ImageSHA256: hex.EncodeToString(h[:])})
	if e != nil {
		return e
	}
	if e = j.atomicWrite(j.path, data, "image"); e != nil {
		return e
	}
	return j.atomicWrite(j.path+".anchor", proof, "anchor")
}

func (j *Journal) atomicWrite(path string, data []byte, kind string) error {
	if j.hook != nil {
		if e := j.hook("before-" + kind); e != nil {
			return e
		}
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".elx-journal-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if e = f.Chmod(0o600); e != nil {
		return e
	}
	if _, e = f.Write(data); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if j.hook != nil {
		if e = j.hook("before-rename-" + kind); e != nil {
			return e
		}
	}
	if e = os.Rename(f.Name(), path); e != nil {
		return e
	}
	if j.hook != nil {
		if e = j.hook("after-rename-" + kind); e != nil {
			return e
		}
	}
	dir, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer dir.Close()
	return dir.Sync()
}
