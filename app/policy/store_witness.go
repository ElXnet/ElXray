package policy

import (
 "crypto/ed25519"
 "errors"
 "fmt"
 "time"

 "github.com/google/uuid"
)

// SignedStoreWitness is supplied over the OS-authenticated local channel by
// the agent, which fetched it over Control mTLS from independent PostgreSQL.
// The core verifies Control's pinned Ed25519 signer, fresh boot challenge,
// correct resource binding and EXACT durable revision before accepting a lease.
type SignedStoreWitness struct {
 Version uint32
 NodeID string
 ResourceID string
 ExecutorID string
 StoreID string
 AuthorityGeneration uint64
 CoreRevision uint64
 CoreIncarnation string
 LastOperationID string
 Nonce string
 NotBefore int64
 NotAfter int64
 Signature []byte
}

func StoreWitnessTranscript(w SignedStoreWitness) []byte {
 if w.Version!=1 {return nil}
 return fmt.Appendf(nil,"elx-control-store-witness-v1\n%s\n%s\n%s\n%s\n%d\n%d\n%s\n%s\n%s\n%d\n%d",
  w.NodeID,w.ResourceID,w.ExecutorID,w.StoreID,w.AuthorityGeneration,w.CoreRevision,
  w.CoreIncarnation,w.LastOperationID,w.Nonce,w.NotBefore,w.NotAfter)
}

// ManagedWitnessNonce changes on every core incarnation. A replayed Control
// witness from a previous boot cannot match a restored local journal.
func (m *Instance) ManagedWitnessNonce(subscription string) (string,error) {
 m.subscriptionMu.Lock()
 defer m.subscriptionMu.Unlock()
 if m.opJournal==nil || m.store==nil || m.store.failed {return "",errors.New("managed durable store is not ready")}
 if _,ok:=m.leaseBindings[subscription];!ok{return "",errors.New("unassigned witness subscription")}
 if m.usageIncarnation==[16]byte{} {return "",errors.New("core incarnation is unavailable")}
 return uuid.UUID(m.usageIncarnation).String(),nil
}

func (m *Instance) verifyStoreWitnessLocked(t ControlLease,w *SignedStoreWitness) error {
 if m.opJournal==nil {return nil}
 now:=time.Now().UTC().Unix()
 binding:=m.leaseBindings[t.Subscription]
 if w==nil || w.Version!=1 || len(w.Signature)!=ed25519.SignatureSize ||
  w.NodeID!=m.leaseNodeID.String() || w.ResourceID!=t.ResourceID.String() ||
  w.ExecutorID!=binding.ExecutorID.String() ||
  w.StoreID!=m.opJournal.StoreID() ||
  w.AuthorityGeneration!=t.AuthorityGeneration ||
  w.Nonce!=uuid.UUID(m.usageIncarnation).String() ||
  w.NotBefore>now+5||w.NotBefore<now-15||
  w.NotAfter<=now||w.NotAfter-w.NotBefore>30||
  !ed25519.Verify(m.leasePublicKey,StoreWitnessTranscript(*w),w.Signature) {
  return errors.New("invalid, expired or replayed signed Control store witness")
 }
 revision,generation,ok:=m.opJournal.ResourceState(t.ResourceID.String())
 if !ok || revision!=w.CoreRevision || revision!=m.subscriptionPolicies[t.Subscription].Revision ||
  generation!=w.AuthorityGeneration {
  return errors.New("independent Control revision/HWM disagrees with local durable state")
 }
 // Master also attests the committed operation's last ID/incarnation. The
 // local journal must contain the exact applied receipt if nonempty.
 if w.LastOperationID!="" || w.CoreIncarnation!="" {
  id,parseErr:=uuid.Parse(w.LastOperationID)
  inc,incErr:=uuid.Parse(w.CoreIncarnation)
  if parseErr!=nil||incErr!=nil||id==uuid.Nil||inc==uuid.Nil {
   return errors.New("invalid Control store incarnation/operation")
  }
  receipt,exists:=m.opJournal.Get(w.LastOperationID)
  if !exists||receipt.State!="APPLIED"||receipt.ResourceID!=w.ResourceID||
   receipt.NewRevision!=w.CoreRevision {
   return errors.New("witness describes an operation missing from recovered journal")
  }
 }
 return nil
}
