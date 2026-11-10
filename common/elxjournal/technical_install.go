package elxjournal

import (
	"crypto/sha256"
	"encoding/hex"
)

// BeginTechnicalInstall persists an install INTENT before the VLESS validator
// can be mutated. A failed/uncertain live change must not be retried as a new
// operation or reported INSTALLED. This journal is not an admission grant.
func (j *Journal) BeginTechnicalInstall(profileID, operationID, transcriptDigest, flow string,
	revision, authority uint64) (TechnicalProfile, error) {
	if j == nil {
		return TechnicalProfile{}, ErrInvalid
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.failed {
		return TechnicalProfile{}, ErrCorrupt
	}
	if !uuidRE.MatchString(profileID) || !uuidRE.MatchString(operationID) ||
		(flow != "" && flow != "xtls-rprx-vision") || revision == 0 || authority == 0 {
		return TechnicalProfile{}, ErrInvalid
	}
	digest, err := hex.DecodeString(transcriptDigest)
	if err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != transcriptDigest {
		return TechnicalProfile{}, ErrInvalid
	}
	p, ok := j.img.TechnicalProfiles[profileID]
	if !ok {
		return TechnicalProfile{}, ErrStale
	}
	if p.Phase == "INSTALLING" {
		return TechnicalProfile{}, ErrUncertain
	}
	if p.Phase == "INSTALLED" {
		if p.InstallOperationID == operationID && p.InstallTranscriptSHA256 == transcriptDigest && p.Flow == flow {
			return p, nil
		}
		return TechnicalProfile{}, ErrCollision
	}
	if p.Phase != "PREPARED" || p.OperationID == operationID ||
		p.PolicyRevision != revision || p.AuthorityGeneration != authority ||
		j.img.Revisions[p.ResourceID] != revision || j.img.Generations[p.ResourceID] != authority ||
		j.HasPendingLocked(p.ResourceID) {
		return TechnicalProfile{}, ErrStale
	}
	for _, q := range j.img.TechnicalProfiles {
		if q.InstallOperationID == operationID {
			return TechnicalProfile{}, ErrCollision
		}
	}
	if j.img.DeniedProfiles[profileID] != 0 {
		return TechnicalProfile{}, ErrStale
	}
	next := snapshot(j.img)
	p.Phase = "INSTALLING"
	p.InstallOperationID = operationID
	p.InstallTranscriptSHA256 = transcriptDigest
	p.Flow = flow
	next.TechnicalProfiles[profileID] = p
	if err := j.persist(next); err != nil {
		j.failed = true
		return TechnicalProfile{}, err
	}
	j.img = next
	return p, nil
}

// MarkTechnicalInstalled requires external verified live VLESS GetUser before
// this call. The persisted status is a technical registration, NOT device proof
// and NOT a core-signed Control APPLIED receipt.
func (j *Journal) MarkTechnicalInstalled(profileID, operationID string) (TechnicalProfile, error) {
	if j == nil {
		return TechnicalProfile{}, ErrInvalid
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.failed {
		return TechnicalProfile{}, ErrCorrupt
	}
	p, ok := j.img.TechnicalProfiles[profileID]
	if !ok || p.InstallOperationID != operationID {
		return TechnicalProfile{}, ErrStale
	}
	if p.Phase == "INSTALLED" {
		return p, nil
	}
	if p.Phase != "INSTALLING" {
		return TechnicalProfile{}, ErrUncertain
	}
	next := snapshot(j.img)
	p.Phase = "INSTALLED"
	next.TechnicalProfiles[profileID] = p
	if err := j.persist(next); err != nil {
		j.failed = true
		return TechnicalProfile{}, err
	}
	j.img = next
	return p, nil
}
