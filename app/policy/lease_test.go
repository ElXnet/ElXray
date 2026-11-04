package policy

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"errors"
	"testing"
	"time"
	"github.com/google/uuid"
	"github.com/xtls/xray-core/common/subscriptionrate"
)

func TestSignedControlLeaseRequiresNodeAndAbsoluteExpiry(t *testing.T) {
	pub,key,err:=ed25519.GenerateKey(nil)
	if err!=nil {t.Fatal(err)}
	node:=uuid.New()
	state:=filepath.Join(t.TempDir(),"policy.json")
	_,coreKey,err:=ed25519.GenerateKey(nil)
	if err!=nil {t.Fatal(err)}
	if err:=os.WriteFile(state,[]byte("{\"Version\":1}"),0600);err!=nil {t.Fatal(err)}
	if err:=os.WriteFile(state+".key",[]byte(hex.EncodeToString(coreKey.Seed())),0600);err!=nil {t.Fatal(err)}
	t.Setenv("ELXRAY_POLICY_STATE",state)
	t.Setenv("ELXRAY_REQUIRE_CONTROL_LEASE","1")
	t.Setenv("ELXRAY_CONTROL_LEASE_PUBLIC_KEY",base64.StdEncoding.EncodeToString(pub))
	t.Setenv("ELXRAY_CONTROL_LEASE_NODE_UUID",node.String())
	m,err:=New(context.Background(),&Config{RequireSubscription:true,
		Subscriptions:map[string]*SubscriptionPolicy{
			"lab":{Emails:[]string{"member"},UplinkBps:100,DownlinkBps:200},
		}})
	if err!=nil {t.Fatal(err)}
	defer m.Close()
	limit:=m.ForEmail("member")
	if limit==nil {t.Fatal("missing budget")}
	if err:=limit.Downlink.WaitN(context.Background(),1);!errors.Is(err,subscriptionrate.ErrDisabled){
		t.Fatal("unleased subscription was active:",err)
	}
	now:=time.Now().Unix()
	ticket:=ControlLease{NodeID:node,Subscription:"lab",Sequence:1,
		NotBefore:now,NotAfter:now+15}
	sign:=func(tick ControlLease)ControlLease{
		tick.Signature=ed25519.Sign(key,ControlLeaseTranscript(tick))
		return tick
	}
	for _,bad:=range []ControlLease{
		{NodeID:uuid.New(),Subscription:"lab",Sequence:1,NotBefore:now,NotAfter:now+15},
		{NodeID:node,Subscription:"other",Sequence:1,NotBefore:now,NotAfter:now+15},
		{NodeID:node,Subscription:"lab",Sequence:1,NotBefore:now+8,NotAfter:now+15},
		{NodeID:node,Subscription:"lab",Sequence:1,NotBefore:now,NotAfter:now+120},
		{NodeID:node,Subscription:"lab",Sequence:1,NotBefore:now-60,NotAfter:now+15},
		{NodeID:node,Subscription:"lab",Sequence:0,NotBefore:now,NotAfter:now+15},
	} {
		if err:=m.RenewControlLease(sign(bad));err==nil{t.Fatalf("accepted invalid ticket: %+v",bad)}
	}
	if err:=m.RenewControlLease(sign(ticket));err!=nil {t.Fatal(err)}
	cleanup,err:=limit.TrackConnection(func(){})
	if err!=nil {t.Fatal(err)}
	cleanup()
	if err:=m.RenewControlLease(sign(ticket));err==nil {t.Fatal("Control lease sequence replay accepted")}
	ticket.Sequence=2
	ticket.NotAfter=now+16
	tamper:=sign(ticket)
	tamper.NotAfter=now+25
	if err:=m.RenewControlLease(tamper);err==nil {t.Fatal("tampered unsigned expiry accepted")}
	if err:=m.RenewControlLease(sign(ticket));err!=nil {t.Fatal(err)}
}

func TestLeaseModeRejectsMissingTrustAnchor(t *testing.T){
	t.Setenv("ELXRAY_REQUIRE_CONTROL_LEASE","1")
	t.Setenv("ELXRAY_CONTROL_LEASE_PUBLIC_KEY","")
	t.Setenv("ELXRAY_CONTROL_LEASE_NODE_UUID",uuid.NewString())
	if _,err:=New(context.Background(),&Config{RequireSubscription:true,
		Subscriptions:map[string]*SubscriptionPolicy{"lab":{Emails:[]string{"a"}}}});err==nil{
		t.Fatal("mandatory lease without Control key accepted")
	}
	if _,err:=New(context.Background(),&Config{RequireSubscription:false,
		Subscriptions:map[string]*SubscriptionPolicy{"lab":{Emails:[]string{"a"}}}});err==nil{
		t.Fatal("unmanaged subscription bypassed mandatory Control lease")
	}
}
