package subscriptionrate

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestControlLeaseDenyAndExpiryClosesIdleFlows(t *testing.T) {
	l:=New(100,100)
	l.RequireLease()
	if _,err:=l.TrackConnection(func(){});!errors.Is(err,ErrDisabled) {
		t.Fatalf("core accepted managed device before Control lease: %v",err)
	}
	if err:=l.Uplink.WaitN(context.Background(),1);!errors.Is(err,ErrDisabled){
		t.Fatalf("unleased payload escaped: %v",err)
	}
	deadline:=time.Now().Add(300*time.Millisecond)
	l.RenewLease(deadline)
	var stops atomic.Int32
	end,err:=l.TrackConnection(func(){stops.Add(1)})
	if err!=nil {t.Fatal(err)}
	defer end()
	l.SweepLease(deadline.Add(time.Millisecond))
	if stops.Load()!=1 {t.Fatal("idle VLESS socket not stopped on lease expiry")}
	if _,err:=l.TrackConnection(func(){});!errors.Is(err,ErrDisabled) {
		t.Fatalf("expired lease reopened admission: %v",err)
	}
	if l.Downlink.AllowN(deadline.Add(time.Second),1){t.Fatal("expired lease admitted payload")}
	// Retrying a stale ticket cannot enlarge the deadline.
	l.RenewLease(deadline)
	if _,err:=l.TrackConnection(func(){});!errors.Is(err,ErrDisabled){
		t.Fatal("stale lease retry reopened closed flow")
	}
	l.RenewLease(time.Now().Add(time.Second))
	next,err:=l.TrackConnection(func(){})
	if err!=nil {t.Fatal("fresh lease did not restore managed admission:",err)}
	next()
	l.Update(100,100,true)
	if _,err:=l.TrackConnection(func(){});!errors.Is(err,ErrDisabled) {
		t.Fatal("signed lease overrode explicit disabled subscription")
	}
}
