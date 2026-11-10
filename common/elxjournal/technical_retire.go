package elxjournal

import (
	"crypto/sha256"
	"encoding/hex"
)

// BeginTechnicalRetire atomically persists the profile's RETIRING intent and
// permanent effective-UUID denial. No live VLESS user is removed until this
// snapshot and its anchor are fsynced. Even a process crash leaves all managed
// traffic blocked; the old UUID may never be reissued.
func (j *Journal) BeginTechnicalRetire(profileID, operationID, digest string,
	generation, revision, authority uint64,
) (TechnicalProfile, error) {
	if j == nil {
		return TechnicalProfile{}, ErrInvalid
	}
	if !uuidRE.MatchString(profileID) || !uuidRE.MatchString(operationID) ||
		generation < 2 || revision == 0 || authority == 0 {
		return TechnicalProfile{}, ErrInvalid
	}
	bytes, err := hex.DecodeString(digest)
	if err != nil || len(bytes) != sha256.Size || hex.EncodeToString(bytes) != digest {
		return TechnicalProfile{}, ErrInvalid
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.failed {
		return TechnicalProfile{}, ErrCorrupt
	}
	p, exists := j.img.TechnicalProfiles[profileID]
	if !exists {
		return TechnicalProfile{}, ErrStale
	}
	if p.Phase == "RETIRED" {
		if p.RetireOperationID == operationID &&
			p.RetireTranscriptSHA256 == digest &&
			p.RetireGeneration == generation {
			return p, nil
		}
		return TechnicalProfile{}, ErrCollision
	}
	if p.Phase == "RETIRING" || p.Phase == "INSTALLING" {
		return TechnicalProfile{}, ErrUncertain
	}
	if p.Phase != "PREPARED" && p.Phase != "INSTALLED" {
		return TechnicalProfile{}, ErrStale
	}
	if operationID == p.OperationID || operationID == p.InstallOperationID ||
		revision != p.PolicyRevision || authority != p.AuthorityGeneration ||
		j.img.Revisions[p.ResourceID] != revision ||
		j.img.Generations[p.ResourceID] != authority ||
		j.HasPendingLocked(p.ResourceID) || j.img.DeniedProfiles[profileID] != 0 {
		return TechnicalProfile{}, ErrStale
	}
	for _, existing := range j.img.TechnicalProfiles {
		if existing.OperationID == operationID ||
			existing.InstallOperationID == operationID ||
			existing.RetireOperationID == operationID {
			return TechnicalProfile{}, ErrCollision
		}
	}
	for denied := range j.img.DeniedProfiles {
		if vlessLookupKey(denied) == vlessLookupKey(profileID) {
			return TechnicalProfile{}, ErrCollision
		}
	}
	next := snapshot(j.img)
	p.Phase = "RETIRING"
	p.RetireOperationID = operationID
	p.RetireTranscriptSHA256 = digest
	p.RetireGeneration = generation
	next.TechnicalProfiles[profileID] = p
	next.DeniedProfiles[profileID] = generation
	if err := j.persist(next); err != nil {
		j.failed = true
		return TechnicalProfile{}, err
	}
	j.img = next
	return p, nil
}

// MarkTechnicalRetired must be called only after the concrete VLESS inbound
// confirms that the effective authentication UUID is absent. The journal's
// durable denial was already written before the attempted live removal.
func (j *Journal) MarkTechnicalRetired(profileID, operationID string) (TechnicalProfile, error) {
	if j == nil {
		return TechnicalProfile{}, ErrInvalid
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.failed {
		return TechnicalProfile{}, ErrCorrupt
	}
	p, exists := j.img.TechnicalProfiles[profileID]
	if !exists || p.RetireOperationID != operationID ||
		j.img.DeniedProfiles[profileID] != p.RetireGeneration ||
		p.RetireGeneration <= p.ProfileGeneration {
		return TechnicalProfile{}, ErrStale
	}
	if p.Phase == "RETIRED" {
		return p, nil
	}
	if p.Phase != "RETIRING" {
		return TechnicalProfile{}, ErrUncertain
	}
	next := snapshot(j.img)
	p.Phase = "RETIRED"
	next.TechnicalProfiles[profileID] = p
	if err := j.persist(next); err != nil {
		j.failed = true
		return TechnicalProfile{}, err
	}
	j.img = next
	return p, nil
}
