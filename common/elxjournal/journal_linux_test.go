//go:build linux

package elxjournal

import (
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "os"
 "path/filepath"
 "testing"
)

const (
 testStore = "11111111-1111-4111-8111-111111111111"
 testOperation = "22222222-2222-4222-8222-222222222222"
 testNode = "33333333-3333-4333-8333-333333333333"
 testExecutor = "44444444-4444-4444-8444-444444444444"
 testResource = "55555555-5555-4555-8555-555555555555"
)
func sample() Command {
 h:=sha256.Sum256([]byte("approved rate payload"))
 return Command{OperationID:testOperation,NodeID:testNode,ExecutorID:testExecutor,
 ResourceID:testResource,AuthorityGeneration:9,ExpectedRevision:0,NewRevision:1,
 PayloadSHA256:hex.EncodeToString(h[:]),Kind:"set-rate"}
}
func fresh(t *testing.T) (*Journal,string) {
 t.Helper()
 path:=filepath.Join(t.TempDir(),"ops.json")
 if e:=Provision(path,testStore);e!=nil{t.Fatal(e)}
 j,e:=Open(path);if e!=nil{t.Fatal(e)}
 return j,path
}
func TestIntentApplyDedupAcrossRestartAndWatermarks(t *testing.T){
 j,path:=fresh(t)
 c:=sample()
 r,e:=j.Begin(c)
 if e!=nil||r.State!="INTENT"{t.Fatalf("begin: %+v %v",r,e)}
 j,e=Open(path);if e!=nil{t.Fatal(e)}
 if r,e=j.Begin(c);e!=nil||r.State!="INTENT"{t.Fatalf("duplicate intent: %+v %v",r,e)}
 foreign:=c;foreign.PayloadSHA256="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
 if _,e:=j.Begin(foreign);!errors.Is(e,ErrCollision){t.Fatalf("operation collision accepted: %v",e)}
 other:=c;other.OperationID="66666666-6666-4666-8666-666666666666"
 if _,e:=j.Begin(other);!errors.Is(e,ErrUncertain){t.Fatalf("ambiguous pending operation allowed: %v",e)}
 receipt,e:=j.MarkApplied(testOperation)
 if e!=nil||receipt.State!="APPLIED"||receipt.CompletedUnixNanos==0{t.Fatalf("apply: %+v %v",receipt,e)}
 j,e=Open(path);if e!=nil{t.Fatal(e)}
 if r,e:=j.Begin(c);e!=nil||r.State!="APPLIED"{t.Fatalf("applied retry: %+v %v",r,e)}
 other.ExpectedRevision=0;other.NewRevision=1
 if _,e:=j.Begin(other);!errors.Is(e,ErrStale){t.Fatalf("stale revision: %v",e)}
 other.ExpectedRevision=1;other.NewRevision=2;other.AuthorityGeneration=8
 if _,e:=j.Begin(other);!errors.Is(e,ErrStale){t.Fatalf("stale authority: %v",e)}
 other.AuthorityGeneration=9
 if _,e:=j.Begin(other);e!=nil{t.Fatal(e)}
}
func TestInjectedCrashesNeverAcknowledgeHalfCommit(t *testing.T){
 for _,point:=range []string{"before-image","before-rename-image","after-rename-image",
 "before-anchor","before-rename-anchor","after-rename-anchor"}{
 t.Run(point,func(t *testing.T){
  j,path:=fresh(t)
  j.hook=func(phase string)error{if phase==point{return errors.New("simulated crash")};return nil}
  if _,e:=j.Begin(sample());e==nil{t.Fatal("hook was not triggered")}
  if _,e:=j.Begin(sample());!errors.Is(e,ErrCorrupt){t.Fatalf("continued after storage error: %v",e)}
  reopened,e:=Open(path)
  switch point {
  case "before-image","before-rename-image":
   if e!=nil{t.Fatal(e)}
   if _,ok:=reopened.Get(testOperation);ok{t.Fatal("unexpected intent")}
  case "after-rename-anchor":
   if e!=nil{t.Fatal(e)}
   r,ok:=reopened.Get(testOperation)
   if !ok||r.State!="INTENT"{t.Fatal("lost ambiguous intent")}
  default:
   if !errors.Is(e,ErrCorrupt){t.Fatalf("inconsistent file pair reopened: %v",e)}
  }
 })
 }
}
func TestRollbackAndDamageDoNotSilentlyRestorePrivileges(t *testing.T){
 j,path:=fresh(t)
 older,e:=os.ReadFile(path);if e!=nil{t.Fatal(e)}
 if _,e=j.Begin(sample());e!=nil{t.Fatal(e)}
 if _,e=j.MarkApplied(testOperation);e!=nil{t.Fatal(e)}
 if e=os.WriteFile(path,older,0o600);e!=nil{t.Fatal(e)}
 if _,e=Open(path);!errors.Is(e,ErrCorrupt){t.Fatalf("one-file rollback accepted: %v",e)}
 _,path=fresh(t)
 if e=os.WriteFile(path+".anchor",[]byte("not-json"),0o600);e!=nil{t.Fatal(e)}
 if _,e=Open(path);!errors.Is(e,ErrCorrupt){t.Fatalf("torn anchor accepted: %v",e)}
}
func TestNoImplicitInitializeAndInvalidExecutor(t *testing.T){
 path:=filepath.Join(t.TempDir(),"journal.json")
 if _,e:=Open(path);e==nil{t.Fatal("absent journal treated as empty")}
 if e:=Provision(path,testStore);e!=nil{t.Fatal(e)}
 if e:=Provision(path,testStore);!errors.Is(e,ErrCorrupt){t.Fatalf("overwrite existing journal: %v",e)}
 j,e:=Open(path);if e!=nil{t.Fatal(e)}
 c:=sample();c.ExecutorID="not-a-uuid"
 if _,e=j.Begin(c);!errors.Is(e,ErrInvalid){t.Fatalf("malformed executor accepted: %v",e)}
}

func TestDurableLeaseHighWaterSurvivesRestart(t *testing.T) {
 j,path:=fresh(t)
 if e:=j.RecordVerifiedLease(testResource,9,100,1700000015);e!=nil {t.Fatal(e)}
 if e:=j.RecordVerifiedLease(testResource,9,100,1700000015);!errors.Is(e,ErrStale){t.Fatalf("replayed signed lease: %v",e)}
 if e:=j.RecordVerifiedLease(testResource,8,101,1700000016);!errors.Is(e,ErrStale){t.Fatalf("old authority accepted: %v",e)}
 rebooted,e:=Open(path);if e!=nil {t.Fatal(e)}
 if w,ok:=rebooted.Lease(testResource);!ok||w.AuthorityGeneration!=9||w.Sequence!=100 {
  t.Fatalf("durable lease watermark lost: %+v %v",w,ok)
 }
 if e:=rebooted.RecordVerifiedLease(testResource,9,99,1700000018);!errors.Is(e,ErrStale) {
  t.Fatalf("old signed sequence accepted after restart: %v",e)
 }
 if e:=rebooted.RecordVerifiedLease(testResource,10,101,1700000020);e!=nil {t.Fatal(e)}
 if w,_:=rebooted.Lease(testResource);w.AuthorityGeneration!=10||w.Sequence!=101{t.Fatal(w)}
}

func TestLeaseHighWaterCrashNeverReopensUnknownAuthority(t *testing.T) {
 for _,phase:=range []string{"before-image","after-rename-image","before-anchor","after-rename-anchor"} {
  t.Run(phase,func(t *testing.T) {
   j,path:=fresh(t)
   j.hook=func(point string)error{
    if point==phase{return errors.New("fault injected at "+phase)}
    return nil
   }
   if e:=j.RecordVerifiedLease(testResource,9,100,1700000015);e==nil {t.Fatal("fault was ignored")}
   if e:=j.RecordVerifiedLease(testResource,9,101,1700000016);!errors.Is(e,ErrCorrupt) {t.Fatalf("failed journal accepted signed lease: %v",e)}
   reopened,e:=Open(path)
   if phase=="after-rename-image"||phase=="before-anchor" {
    if !errors.Is(e,ErrCorrupt){t.Fatalf("torn lease HWM reopened: %v",e)}
   } else {
    if e!=nil {t.Fatal(e)}
    w,ok:=reopened.Lease(testResource)
    if phase=="after-rename-anchor" && (!ok || w.Sequence!=100) {t.Fatal("completed anchor lost lease HWM")}
    if phase=="before-image" && ok {t.Fatal("pre-commit lease HWM was acknowledged")}
   }
  })
 }
}

func TestDurableVLESSProfileTombstoneNeverSilentlyDisappears(t *testing.T) {
 j,path:=fresh(t)
 profile:="77777777-7777-4777-8777-777777777777"
 if e:=j.BootstrapDeniedProfiles([]string{profile});e!=nil {t.Fatal(e)}
 if e:=j.RecordDeniedProfile(profile,2);e!=nil {t.Fatal(e)}
 reopened,e:=Open(path);if e!=nil {t.Fatal(e)}
 denied:=reopened.DeniedProfiles()
 if denied[profile]!=2 {t.Fatalf("revoked profile resurrection: %+v",denied)}
 if e=reopened.RecordDeniedProfile(profile,1);!errors.Is(e,ErrStale) {
  t.Fatalf("old profile deny generation accepted: %v",e)
 }
 if e=reopened.RecordDeniedProfile(profile,3);e!=nil {t.Fatal(e)}
 if got:=reopened.DeniedProfiles()[profile];got!=3 {t.Fatalf("tombstone HWM lost: %d",got)}
 if e=reopened.BootstrapDeniedProfiles([]string{profile});!errors.Is(e,ErrCollision) {
  t.Fatalf("duplicate old profile bootstrapped over tombstone: %v",e)
 }
}
