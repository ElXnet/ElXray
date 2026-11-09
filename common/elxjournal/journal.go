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
 ErrStale = errors.New("stale revision or authority generation")
 ErrCorrupt = errors.New("journal damaged or inconsistent; Control reconciliation required")
 ErrInvalid = errors.New("invalid managed operation")
)
const formatVersion = 2
const maxBytes = 16 << 20
var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type Command struct {
 OperationID string `json:"operationId"`
 NodeID string `json:"nodeId"`
 ExecutorID string `json:"executorId"`
 ResourceID string `json:"resourceId"`
 AuthorityGeneration uint64 `json:"authorityGeneration"`
 ExpectedRevision uint64 `json:"expectedRevision"`
 NewRevision uint64 `json:"newRevision"`
 PayloadSHA256 string `json:"payloadSha256"`
 Kind string `json:"kind"`
}
type Receipt struct {
 Command
 State string `json:"state"`
 CompletedUnixNanos int64 `json:"completedUnixNanos,omitempty"`
}
type image struct {
 Version int `json:"version"`
 StoreID string `json:"storeId"`
 Sequence uint64 `json:"sequence"`
 Operations map[string]Receipt `json:"operations"`
 Revisions map[string]uint64 `json:"revisions"`
 Generations map[string]uint64 `json:"generations"`
}
type anchor struct {
 Version int `json:"version"`
 StoreID string `json:"storeId"`
 Sequence uint64 `json:"sequence"`
 ImageSHA256 string `json:"imageSha256"`
}
type Journal struct {
 mu sync.Mutex
 path string
 img image
 failed bool
 hook func(string) error // unexported crash-injection hook, tests only
}
func validPath(path string) bool { return filepath.IsAbs(path) && path != string(filepath.Separator) }
func validCommand(c Command) bool {
 for _,id := range []string{c.OperationID,c.NodeID,c.ExecutorID,c.ResourceID} {
  if !uuidRE.MatchString(id) || id == "00000000-0000-0000-0000-000000000000" { return false }
 }
 if c.AuthorityGeneration==0 || c.NewRevision==0 || c.NewRevision!=c.ExpectedRevision+1 ||
 c.NewRevision<=c.ExpectedRevision || len(c.PayloadSHA256)!=64 || len(c.Kind)==0 || len(c.Kind)>64 { return false }
 raw,e:=hex.DecodeString(c.PayloadSHA256)
 return e==nil && hex.EncodeToString(raw)==c.PayloadSHA256
}
func protectedRead(path string) ([]byte,error) {
 st,e:=os.Lstat(path);if e!=nil{return nil,e}
 if !st.Mode().IsRegular() || st.Size()>maxBytes || (runtime.GOOS!="windows" && st.Mode().Perm()&0o077!=0) {return nil,ErrCorrupt}
 f,e:=os.Open(path);if e!=nil{return nil,e};defer f.Close()
 data,e:=io.ReadAll(io.LimitReader(f,maxBytes+1));if e!=nil||len(data)>maxBytes{return nil,ErrCorrupt}
 return data,nil
}
func snapshot(s image) image {
 s.Operations=maps.Clone(s.Operations);s.Revisions=maps.Clone(s.Revisions);s.Generations=maps.Clone(s.Generations)
 return s
}
// Provision is an explicit one-time deployment operation, never an automatic
// recovery fallback. Failure midway requires reconciliation, not re-creation.
func Provision(path,storeID string) error {
 if !validPath(path) || !uuidRE.MatchString(storeID) {return ErrInvalid}
 for _,name:=range []string{path,path+".anchor"} {
  _,e:=os.Lstat(name)
  if e==nil {return ErrCorrupt};if !os.IsNotExist(e){return e}
 }
 j:=&Journal{path:path}
 return j.persist(image{Version:formatVersion,StoreID:storeID,Operations:map[string]Receipt{},Revisions:map[string]uint64{},Generations:map[string]uint64{}})
}
// Open fails on a missing anchor, incomplete commit, altered file or single
// snapshot rollback. Coordinated rollback of both files requires a REMOTE
// monotonic Control watermark: local hashes cannot prevent that attack.
func Open(path string) (*Journal,error) {
 if !validPath(path) {return nil,ErrInvalid}
 data,e:=protectedRead(path);if e!=nil{return nil,fmt.Errorf("journal image: %w",e)}
 stamp,e:=protectedRead(path+".anchor");if e!=nil{return nil,fmt.Errorf("journal anchor: %w",e)}
 var s image;var a anchor
 if json.Unmarshal(data,&s)!=nil || json.Unmarshal(stamp,&a)!=nil ||
 s.Version!=formatVersion || a.Version!=formatVersion || s.StoreID!=a.StoreID ||
 !uuidRE.MatchString(s.StoreID) || s.Sequence!=a.Sequence || s.Operations==nil ||
 s.Revisions==nil || s.Generations==nil {return nil,ErrCorrupt}
 sum:=sha256.Sum256(data)
 if a.ImageSHA256!=hex.EncodeToString(sum[:]) {return nil,ErrCorrupt}
 for id,r:=range s.Operations {
  if id!=r.OperationID || !validCommand(r.Command) || (r.State!="INTENT" && r.State!="APPLIED") {return nil,ErrCorrupt}
 }
 return &Journal{path:path,img:s},nil
}
func (j *Journal) Get(id string) (Receipt,bool) {
 j.mu.Lock();defer j.mu.Unlock()
 r,ok:=j.img.Operations[id];return r,ok
}
// Begin durably records INTENT *before* any live change. Duplicate IDs must
// match every signed identity and payload field, not just the hash.
func (j *Journal) Begin(c Command) (Receipt,error) {
 j.mu.Lock();defer j.mu.Unlock()
 if j.failed {return Receipt{},ErrCorrupt}
 if !validCommand(c) {return Receipt{},ErrInvalid}
 if r,ok:=j.img.Operations[c.OperationID];ok {
  if r.Command!=c {return Receipt{},ErrCollision}
  return r,nil
 }
 if j.img.Revisions[c.ResourceID]!=c.ExpectedRevision || c.AuthorityGeneration<j.img.Generations[c.ResourceID] {
  return Receipt{},ErrStale
 }
 for _,r:=range j.img.Operations {
  if r.ResourceID==c.ResourceID && r.State=="INTENT" {return Receipt{},ErrUncertain}
 }
 next:=snapshot(j.img)
 r:=Receipt{Command:c,State:"INTENT"}
 next.Operations[c.OperationID]=r
 if e:=j.persist(next);e!=nil{j.failed=true;return Receipt{},e}
 j.img=next
 return r,nil
}
// MarkApplied must follow authenticated live core readback. A failed storage
// transition leaves the result UNKNOWN; the caller MUST NOT free allocations.
func (j *Journal) MarkApplied(id string) (Receipt,error) {
 j.mu.Lock();defer j.mu.Unlock()
 if j.failed {return Receipt{},ErrCorrupt}
 r,ok:=j.img.Operations[id];if !ok{return Receipt{},ErrInvalid}
 if r.State=="APPLIED" {return r,nil}
 if r.State!="INTENT" || j.img.Revisions[r.ResourceID]!=r.ExpectedRevision ||
 r.AuthorityGeneration<j.img.Generations[r.ResourceID] {return Receipt{},ErrStale}
 next:=snapshot(j.img)
 r.State="APPLIED";r.CompletedUnixNanos=time.Now().UTC().UnixNano()
 next.Operations[id]=r
 next.Revisions[r.ResourceID]=r.NewRevision
 next.Generations[r.ResourceID]=r.AuthorityGeneration
 if e:=j.persist(next);e!=nil{j.failed=true;return Receipt{},e}
 j.img=next
 return r,nil
}
func (j *Journal) persist(next image) error {
 next.Sequence++
 data,e:=json.Marshal(next);if e!=nil{return e};if len(data)>maxBytes{return ErrInvalid}
 h:=sha256.Sum256(data)
 proof,e:=json.Marshal(anchor{Version:formatVersion,StoreID:next.StoreID,Sequence:next.Sequence,ImageSHA256:hex.EncodeToString(h[:])})
 if e!=nil{return e}
 if e=j.atomicWrite(j.path,data,"image");e!=nil{return e}
 return j.atomicWrite(j.path+".anchor",proof,"anchor")
}
func (j *Journal) atomicWrite(path string,data []byte,kind string) error {
 if j.hook!=nil {if e:=j.hook("before-"+kind);e!=nil{return e}}
 f,e:=os.CreateTemp(filepath.Dir(path),".elx-journal-*");if e!=nil{return e}
 defer os.Remove(f.Name());defer f.Close()
 if e=f.Chmod(0o600);e!=nil{return e}
 if _,e=f.Write(data);e!=nil{return e}
 if e=f.Sync();e!=nil{return e}
 if e=f.Close();e!=nil{return e}
 if j.hook!=nil {if e=j.hook("before-rename-"+kind);e!=nil{return e}}
 if e=os.Rename(f.Name(),path);e!=nil{return e}
 if j.hook!=nil {if e=j.hook("after-rename-"+kind);e!=nil{return e}}
 dir,e:=os.Open(filepath.Dir(path));if e!=nil{return e};defer dir.Close()
 return dir.Sync()
}
