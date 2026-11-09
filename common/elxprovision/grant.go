// Package elxprovision defines signed technical VLESS profile preparation.
// A signed preparation does NOT prove device possession and NEVER permits
// payload admission. The separate device/owner admission path owns that gate.
package elxprovision

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalid = errors.New("invalid managed profile grant")
	ErrUnauthorized = errors.New("managed profile grant signature or scope invalid")
	ErrStale = errors.New("stale managed profile generation")
	ErrCollision = errors.New("managed profile operation ID collision")
	ErrNotPrepared = errors.New("managed profile is not prepared")
)

var token = regexp.MustCompile(`^[A-Za-z0-9_.@+:-]{1,255}$`)
var tag = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)

type Action string

const (
	Prepare Action = "prepare"
	Retire Action = "retire"
)

// Grant binds an intended technical profile to a specific Control resource,
// executor, entitlement subscription and inbound. An operator may sign it
// only after recording the reservation in Control's authoritative store.
type Grant struct {
	Version uint32
	Action Action
	OperationID uuid.UUID
	NodeID uuid.UUID
	ExecutorID uuid.UUID
	ResourceID uuid.UUID
	ProfileID uuid.UUID
	SubscriptionID string
	Email string
	InboundTag string
	ProfileGeneration uint64
	AuthorityGeneration uint64
	PolicyRevision uint64
	NotBefore int64
	NotAfter int64
	Signature []byte
}

func (g Grant) Transcript() []byte {
	return fmt.Appendf(nil, "elx-profile-grant-v1\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%d\n%d\n%d\n%d\n%d",
		g.Action, g.OperationID, g.NodeID, g.ExecutorID, g.ResourceID,
		g.ProfileID, g.SubscriptionID, g.Email, g.InboundTag,
		"vless", g.ProfileGeneration, g.AuthorityGeneration, g.PolicyRevision, g.NotBefore, g.NotAfter)
}

func (g Grant) wellFormed() bool {
	if g.Version != 1 || (g.Action != Prepare && g.Action != Retire) ||
		g.OperationID == uuid.Nil || g.NodeID == uuid.Nil ||
		g.ExecutorID == uuid.Nil || g.ResourceID == uuid.Nil || g.ProfileID == uuid.Nil ||
		g.ProfileGeneration == 0 || g.AuthorityGeneration == 0 || g.PolicyRevision == 0 ||
		!token.MatchString(g.SubscriptionID) || !token.MatchString(g.Email) ||
		!tag.MatchString(g.InboundTag) || strings.ContainsAny(g.Email, "\r\n") ||
		g.NotAfter <= g.NotBefore || g.NotAfter-g.NotBefore > 60 ||
		len(g.Signature) != ed25519.SignatureSize {
		return false
	}
	return true
}

// Verify is explicitly scoped by the independently pinned Control signing
// key plus the node, executor and resource. Caller-supplied keys do not count.
func Verify(g Grant, key ed25519.PublicKey, node, executor, resource uuid.UUID, now time.Time) error {
	if !g.wellFormed() {
		return ErrInvalid
	}
	if len(key) != ed25519.PublicKeySize ||
		g.NodeID != node || g.ExecutorID != executor || g.ResourceID != resource ||
		g.NotBefore > now.Unix()+5 || g.NotAfter <= now.Unix() ||
		!ed25519.Verify(key, g.Transcript(), g.Signature) {
		return ErrUnauthorized
	}
	return nil
}

type Phase uint8

const (
	Pending Phase = iota + 1
	Installed
	Retired
)

type Entry struct {
	Grant Grant
	Phase Phase
}

// Registry is a non-authoritative in-memory projection of validated Control
// grants; persistent HWM, operation dedup and core user mutations MUST be
// committed in ElXray's journal before this projection is updated.
// In particular Installed is not equivalent to ADMITTED: device admission
// must be separately proved at the actual VPN data path.
type Registry struct {
	mu sync.RWMutex
	byProfile map[uuid.UUID]Entry
	byOperation map[uuid.UUID]uuid.UUID
}
func New() *Registry {
	return &Registry{byProfile: make(map[uuid.UUID]Entry), byOperation: make(map[uuid.UUID]uuid.UUID)}
}

func (r *Registry) StageVerified(g Grant) error {
	if !g.wellFormed() {
		return ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if prior, exists := r.byOperation[g.OperationID]; exists {
		e := r.byProfile[prior]
		if prior == g.ProfileID && e.Grant.Action == g.Action &&
			string(e.Grant.Transcript()) == string(g.Transcript()) {
			return nil
		}
		return ErrCollision
	}
	if previous, ok := r.byProfile[g.ProfileID]; ok {
		if g.ProfileGeneration <= previous.Grant.ProfileGeneration {
			return ErrStale
		}
		// Terminal profile identity is not reusable. New generations must
		// use a fresh VLESS UUID to prevent silent revival of drained flows.
		if previous.Phase == Retired {
			return ErrStale
		}
	}
	phase := Pending
	if g.Action == Retire {
		phase = Retired
	}
	r.byProfile[g.ProfileID] = Entry{Grant:g, Phase:phase}
	r.byOperation[g.OperationID] = g.ProfileID
	return nil
}

func (r *Registry) MarkInstalled(profile, operation uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.byProfile[profile]
	if !ok || e.Grant.OperationID != operation || e.Grant.Action != Prepare || e.Phase == Retired {
		return ErrNotPrepared
	}
	e.Phase = Installed
	r.byProfile[profile] = e
	return nil
}

func (r *Registry) Get(profile uuid.UUID) (Entry,bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e,ok := r.byProfile[profile]
	if !ok{return Entry{},false}
	e.Grant.Signature = append([]byte(nil),e.Grant.Signature...)
	return e,true
}

// Not an admission decision: signed preparation alone cannot create a
// session/owner, bypass device proof or grant unrestricted VPN payload.
func (r *Registry) PayloadAuthorized(uuid.UUID) bool { return false }
