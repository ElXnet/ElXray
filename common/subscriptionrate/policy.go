package subscriptionrate

import "errors"

var (
	ErrNotFound     = errors.New("subscription not found")
	ErrConflict     = errors.New("subscription revision conflict")
	ErrInvalid      = errors.New("invalid subscription update")
	ErrUnauthorized = errors.New("managed subscription update exceeds signed Control authority")
)

// Policy is a detached management snapshot. Email bindings are immutable at runtime.
type Policy struct {
	ID          string
	Emails      []string
	UplinkBps   uint64
	DownlinkBps uint64
	Revision    uint64
	Disabled    bool
}

// Update changes an existing subscription only. Explicit zero rates mean unlimited;
// disabling is separate. CAS and idempotent retries protect against stale delivery.
type Update struct {
	ID               string
	ExpectedRevision uint64
	Revision         uint64
	UplinkBps        uint64
	DownlinkBps      uint64
	Disabled         bool
}
