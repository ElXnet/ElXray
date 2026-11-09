//go:build linux

package main

import (
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "os"
 "path/filepath"
 "testing"

 "github.com/xtls/xray-core/common/elxjournal"
)

func TestOfflineManagedSnapshotMigrationRetainsBindingsAndDenials(t *testing.T){
 dir:=t.TempDir()
 state:=filepath.Join(dir,"policy.json")
 journalPath:=filepath.Join(dir,"operations.json")
 bindingPath:=filepath.Join(dir,"bindings.json")
 storeID:="11111111-1111-4111-8111-111111111111"
 resource:="22222222-2222-4222-8222-222222222222"
 executor:="33333333-3333-4333-8333-333333333333"
 profile:="77777777-7777-4777-8777-777777777777"
 const denyHex="77777777777747778777777777777777"
 _=profile
 policy:=map[string]any{"ID":"lab","Revision":1,"Emails":[]string{"user"},
  "UplinkBps":uint64(100),"DownlinkBps":uint64(200),"Disabled":false}
 v1:=map[string]any{"Version":1,"Base":map[string]any{"lab":policy},
  "Current":map[string]any{"lab":policy},"DeniedProfiles":[]string{denyHex}}
 encoded,e:=json.Marshal(v1);if e!=nil{t.Fatal(e)}
 if e=os.WriteFile(state,encoded,0o600);e!=nil{t.Fatal(e)}
 manifest:=map[string]binding{"lab":{ResourceID:resource,ExecutorID:executor,MinAuthorityGeneration:9}}
 raw,e:=json.Marshal(manifest);if e!=nil{t.Fatal(e)}
 if e=os.WriteFile(bindingPath,raw,0o600);e!=nil{t.Fatal(e)}
 h:=sha256.Sum256(encoded)
 args:=[]string{"-state",state,"-journal",journalPath,"-bindings",bindingPath,
  "-store",storeID,"-expected-sha256",hex.EncodeToString(h[:]),
  "-approve","OFFLINE_CONTROL_APPROVED"}
 denied:=append([]string(nil),args...)
 denied[len(denied)-1]="wrong"
 if e=run(denied);e==nil {t.Fatal("migration ran without explicit operator approval")}
 if _,e=os.Stat(journalPath);!os.IsNotExist(e){t.Fatal("denied migration created journal")}
 if e=run(args);e!=nil{t.Fatal(e)}
 migrated,e:=os.ReadFile(state);if e!=nil{t.Fatal(e)}
 var snapshot map[string]json.RawMessage
 if e=json.Unmarshal(migrated,&snapshot);e!=nil{t.Fatal(e)}
 var version int;var storedID string
 if json.Unmarshal(snapshot["Version"],&version)!=nil ||
  json.Unmarshal(snapshot["StoreID"],&storedID)!=nil || version!=2||storedID!=storeID{
  t.Fatal("v2 store identity missing")
 }
 j,e:=elxjournal.Open(journalPath);if e!=nil{t.Fatal(e)}
 if rev,gen,ok:=j.ResourceState(resource);!ok||rev!=1||gen!=9{
  t.Fatalf("managed journal initial authority not preserved: %d %d %v",rev,gen,ok)
 }
 if j.DeniedProfiles()[profile]==0 {t.Fatal("v1 revoked VLESS profile was resurrected")}
 if _,e=os.Stat(state+".stage3-v1.backup");e!=nil{t.Fatal("no durable v1 backup:",e)}
 if e=run(args);e==nil {t.Fatal("second migration overwrote provisioned state")}
}
