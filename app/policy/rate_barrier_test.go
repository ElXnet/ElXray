//go:build linux

package policy

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common/subscriptionrate"
	feature "github.com/xtls/xray-core/features/policy"
)

func TestSignedRateBarrierRequiresDurablePolicyAndDrain(t *testing.T){
	path:=filepath.Join(t.TempDir(),"state.json")
	pub,priv,err:=ed25519.GenerateKey(nil)
	if err!=nil {t.Fatal(err)}
	if err:=os.WriteFile(path,[]byte("{\"Version\":1}"),0600);err!=nil{t.Fatal(err)}
	if err:=os.WriteFile(path+".key",[]byte(hex.EncodeToString(priv.Seed())),0600);err!=nil{t.Fatal(err)}
	t.Setenv("ELXRAY_POLICY_STATE",path)
	m,err:=New(context.Background(),&Config{RequireSubscription:true,
		Subscriptions:map[string]*SubscriptionPolicy{"a":{
			Emails:[]string{"member"},UplinkBps:1000,DownlinkBps:1000,Revision:1,
		}}})
	if err!=nil {t.Fatal(err)}
	defer m.Close()
	_,err=m.UpdateSubscription(subscriptionrate.Update{ID:"a",ExpectedRevision:1,Revision:2,
		UplinkBps:200,DownlinkBps:300})
	if err!=nil {t.Fatal(err)}
	req:=feature.RateBarrierRequest{EntitlementID:uuid.New(),NodeID:uuid.New(),
		ResourceID:uuid.New(),OperationID:uuid.New(),Subscription:"a",
		Epoch:1,Revision:1,CoreRevision:2,Up:200,Down:300}
	bad:=req
	bad.Up=400
	if _,err:=m.ProveRateBarrier(context.Background(),bad);err==nil {
		t.Fatal("core signed barrier for unapplied rate")
	}
	limit:=m.ForEmail("member")
	stopped:=make(chan struct{})
	untrack,err:=limit.TrackConnection(func(){close(stopped)})
	if err!=nil{t.Fatal(err)}
	ctx,cancel:=context.WithTimeout(context.Background(),2*time.Second)
	defer cancel()
	type result struct{sig []byte;err error}
	completed:=make(chan result,1)
	go func(){sig,err:=m.ProveRateBarrier(ctx,req);completed<-result{sig,err}}()
	select{case <-stopped:case <-time.After(time.Second):t.Fatal("old flows not stopped")}
	select{case res:=<-completed:t.Fatalf("signed before old flow exit: %v",res.err);default:}
	untrack()
	select{
	case res:=<-completed:
		if res.err!=nil {t.Fatal(res.err)}
		msg:=fmt.Appendf(nil,"elx-rate-barrier-v1\n%s\n%s\n%s\n%s\n%d\n%d\n%d\n%d",
			req.EntitlementID,req.NodeID,req.ResourceID,req.OperationID,
			req.Epoch,req.Revision,req.Up,req.Down)
		if !ed25519.Verify(pub,msg,res.sig) {t.Fatal("signed rate barrier transcript mismatches ledger")}
	case <-time.After(time.Second):t.Fatal("barrier did not complete after all connections exited")
	}
	if next,err:=limit.TrackConnection(func(){});err!=nil {
		t.Fatal("lower live rate policy remained blocked",err)
	}else{next()}
}
