package elxjournal

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// TechnicalProfile is the durable non-admitting record of a Control-signed
// technical VLESS identity. PREPARED never implies live Xray registration,
// authenticated device ownership, a free slot or permission to pass payload.
type TechnicalProfile struct {
	ProfileID           string `json:"profileId"`
	OperationID         string `json:"operationId"`
	NodeID              string `json:"nodeId"`
	ResourceID          string `json:"resourceId"`
	ExecutorID          string `json:"executorId"`
	SubscriptionID      string `json:"subscriptionId"`
	Email               string `json:"email"`
	InboundTag          string `json:"inboundTag"`
	ProfileGeneration   uint64 `json:"profileGeneration"`
	AuthorityGeneration uint64 `json:"authorityGeneration"`
	PolicyRevision      uint64 `json:"policyRevision"`
	NotAfterUnix        int64  `json:"notAfterUnix"`
	TranscriptSHA256    string `json:"transcriptSha256"`
	Phase               string `json:"phase"`
}

func validTechnicalProfile(p TechnicalProfile) bool {
	for _, id := range []string{p.ProfileID, p.OperationID, p.NodeID, p.ResourceID, p.ExecutorID} {
		if !uuidRE.MatchString(id) || id == "00000000-0000-0000-0000-000000000000" {
			return false
		}
	}
	if p.ProfileGeneration != 1 || p.AuthorityGeneration == 0 ||
		p.PolicyRevision == 0 || p.NotAfterUnix <= 0 ||
		p.Phase != "PREPARED" || len(p.SubscriptionID) == 0 ||
		len(p.SubscriptionID) > 1024 || len(p.Email) == 0 ||
		len(p.Email) > 255 || len(p.InboundTag) == 0 ||
		len(p.InboundTag) > 128 ||
		strings.ContainsAny(p.SubscriptionID+p.Email+p.InboundTag, "\r\n") {
		return false
	}
	digest, err := hex.DecodeString(p.TranscriptSHA256)
	return err == nil && len(digest) == sha256.Size &&
		hex.EncodeToString(digest) == p.TranscriptSHA256
}

// vlessLookupKey mirrors proxy/vless.ProcessUUID: the third UUID group
// represents bytes 6 and 7, both ignored by VLESS's effective user lookup.
// We must reject aliases here, before a prepared profile reaches AddUser.
func vlessLookupKey(id string) string {
	if !uuidRE.MatchString(id) {
		return ""
	}
	return id[:14] + "0000" + id[18:]
}

// RecordTechnicalPrepared durably records only a signature-verified,
// exactly bound *preparation*. Callers must independently verify the pinned
// Control key, node/executor/resource, the signed expiry and purchased grant.
// This must complete before any future dynamic VLESS user installation.
// A restored profile UUID or duplicate operation with a different payload
// cannot silently obtain a new identity after crash, rollback or restart.
func (j *Journal) RecordTechnicalPrepared(p TechnicalProfile) error {
	if j == nil || !validTechnicalProfile(p) {
		return ErrInvalid
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.failed {
		return ErrCorrupt
	}
	lookupKey := vlessLookupKey(p.ProfileID)
	// Denied aliases and IDs are permanent even when a caller retries the
	// originally valid preparation after the owner was revoked.
	for deniedID := range j.img.DeniedProfiles {
		if vlessLookupKey(deniedID) == lookupKey {
			return ErrStale
		}
	}
	if existing, ok := j.img.TechnicalProfiles[p.ProfileID]; ok {
		if existing == p {
			return nil
		}
		return ErrCollision
	}
	for _, previous := range j.img.TechnicalProfiles {
		if vlessLookupKey(previous.ProfileID) == lookupKey ||
			previous.OperationID == p.OperationID ||
			(previous.NodeID == p.NodeID &&
				previous.ExecutorID == p.ExecutorID &&
				previous.InboundTag == p.InboundTag &&
				previous.Email == p.Email) {
			return ErrCollision
		}
	}
	revision, ok := j.img.Revisions[p.ResourceID]
	if !ok || revision != p.PolicyRevision ||
		j.img.Generations[p.ResourceID] != p.AuthorityGeneration ||
		j.HasPendingLocked(p.ResourceID) {
		return ErrStale
	}
	if lease, ok := j.img.Leases[p.ResourceID]; ok &&
		lease.AuthorityGeneration > p.AuthorityGeneration {
		return ErrStale
	}
	next := snapshot(j.img)
	if next.TechnicalProfiles == nil {
		next.TechnicalProfiles = make(map[string]TechnicalProfile)
	}
	next.TechnicalProfiles[p.ProfileID] = p
	if err := j.persist(next); err != nil {
		j.failed = true
		return err
	}
	j.img = next
	return nil
}

func (j *Journal) TechnicalProfile(profileID string) (TechnicalProfile, bool) {
	if j == nil {
		return TechnicalProfile{}, false
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.failed {
		return TechnicalProfile{}, false
	}
	p, ok := j.img.TechnicalProfiles[profileID]
	return p, ok
}
