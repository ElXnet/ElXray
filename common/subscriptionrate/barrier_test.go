package subscriptionrate

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRateBarrierWaitsForOldFlowsAndBlocksNewAdmission(t *testing.T) {
	l:=New(100,100)
	stopped:=make(chan struct{})
	untrack,err:=l.TrackConnection(func(){close(stopped)})
	if err!=nil{t.Fatal(err)}
	ctx,cancel:=context.WithTimeout(context.Background(),time.Second)
	defer cancel()
	result:=make(chan error,1)
	go func(){result<-l.DrainForRateBarrier(ctx)}()
	select{
	case <-stopped:
	case <-time.After(time.Second):t.Fatal("barrier did not request existing socket closure")
	}
	if _,err:=l.TrackConnection(func(){});!errors.Is(err,ErrDisabled){
		t.Fatalf("new flow admitted during rate barrier: %v",err)
	}
	if l.Downlink.AllowN(time.Now(),1){t.Fatal("payload escaped rate barrier")}
	select{case err:=<-result:t.Fatalf("signed before flow exit: %v",err);default:}
	untrack()
	select{
	case err:=<-result:if err!=nil{t.Fatal(err)}
	case <-time.After(time.Second):t.Fatal("barrier did not finish after old flow exited")
	}
	next,err:=l.TrackConnection(func(){})
	if err!=nil{t.Fatalf("barrier permanently denied new-rate flows: %v",err)}
	next()
}
