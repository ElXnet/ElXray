// Command elx-technical-inspect is a read-only offline forensic gate for
// managed technical VLESS operations. It never edits journal or Control state.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common/elxjournal"
)

type technicalInspection struct {
	StoreID             string `json:"storeId"`
	ProfileID           string `json:"profileId"`
	OperationID         string `json:"operationId"`
	Phase               string `json:"phase"`
	AuthorityGeneration uint64 `json:"authorityGeneration"`
	PolicyRevision      uint64 `json:"policyRevision"`
	DeniedGeneration    uint64 `json:"deniedGeneration"`
	Uncertain           bool   `json:"uncertain"`
	RequiresIsolation   bool   `json:"requiresIsolation"`
	MutationAllowed     bool   `json:"mutationAllowed"`
}

// inspect requires a separately obtained, exact Control-pinned store ID and
// operation identity. Both the journal image and its fsynced anchor are read
// by elxjournal.Open; malformed or rolled-back snapshots fail closed.
func inspect(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("elx-technical-inspect", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("journal", "", "absolute durable managed journal path")
	statePath := flags.String("policy-state", "", "absolute durable policy state to acquire its exclusive lock")
	store := flags.String("expect-store", "", "independently pinned Control store UUID")
	profile := flags.String("profile", "", "exact technical VLESS profile UUID")
	operation := flags.String("operation", "", "original signed Control operation UUID")
	requireTerminal := flags.Bool("require-terminal", false, "refuse interrupted INSTALLING/RETIRING")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || !filepath.IsAbs(*path) || *statePath == "" || !validUUID(*store) ||
		!validUUID(*profile) || !validUUID(*operation) || output == nil {
		return errors.New("absolute journal and exact store/profile/operation UUIDs required")
	}
	// Exclusively lock the same policy state lock that a managed core holds
	// for its lifetime. Refuse inspection while a live or racing core may
	// mutate users and journal state. Never create a missing lock as a
	// speculative provision or silently run on an unsupported OS.
	lock, err := lockManagedPolicyState(*statePath)
	if err != nil {
		return fmt.Errorf("managed core must be stopped and state lock available: %w", err)
	}
	defer lock.Close()
	j, err := elxjournal.Open(*path)
	if err != nil {
		return fmt.Errorf("managed journal/anchor integrity failure: %w", err)
	}
	localStore, valid := j.StoreIdentity()
	if !valid || localStore != *store {
		return errors.New("independent Control store witness mismatch")
	}
	p, ok := j.TechnicalProfile(*profile)
	if !ok {
		return errors.New("profile not bound to this immutable core journal")
	}
	// A PREPARE ID must not masquerade as evidence for an interrupted
	// INSTALL; likewise the old INSTALL ID cannot certify a RETIRE.
	var phaseOperation string
	switch p.Phase {
	case "PREPARED":
		phaseOperation = p.OperationID
	case "INSTALLING", "INSTALLED":
		phaseOperation = p.InstallOperationID
	case "RETIRING", "RETIRED":
		phaseOperation = p.RetireOperationID
	default:
		return errors.New("invalid technical journal phase")
	}
	if phaseOperation != *operation {
		return errors.New("operation does not match the active durable phase")
	}
	uncertain := p.Phase == "INSTALLING" || p.Phase == "RETIRING"
	if j.HasPending() && !uncertain {
		return errors.New("another unconfirmed managed journal mutation requires quarantine")
	}
	if *requireTerminal && uncertain {
		return errors.New("interrupted technical mutation requires independent operator reconciliation")
	}
	denied := j.DeniedProfiles()[*profile]
	if (p.Phase == "RETIRING" || p.Phase == "RETIRED") &&
		denied != p.RetireGeneration {
		return errors.New("permanent retired UUID tombstone unavailable")
	}
	return json.NewEncoder(output).Encode(technicalInspection{
		StoreID: localStore, ProfileID: *profile, OperationID: *operation,
		Phase: p.Phase, AuthorityGeneration: p.AuthorityGeneration,
		PolicyRevision: p.PolicyRevision, DeniedGeneration: denied,
		Uncertain: uncertain, RequiresIsolation: uncertain,
		MutationAllowed: false,
	})
}

func validUUID(raw string) bool {
	id, err := uuid.Parse(raw)
	return err == nil && id != uuid.Nil && id.String() == raw
}

func main() {
	if err := inspect(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
