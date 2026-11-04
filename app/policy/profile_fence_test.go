//go:build linux

package policy

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common/sessionfence"
	feature "github.com/xtls/xray-core/features/policy"
)

func TestDrainOneAuthenticatedProfileSignsOnlyAfterFlowsExit(t *testing.T) {
	path:=filepath.Join(t.TempDir(),"state.json")
	pub,private,err:=ed25519.GenerateKey(nil)
	if err!=nil {t.Fatal(err)}
	if err:=os.WriteFile(path,[]byte("{\"Version\":1}"),0600);err!=nil {t.Fatal(err)}
	if err:=os.WriteFile(path+".key",[]byte(hex.EncodeToString(private.Seed())),0600);err!=nil {t.Fatal(err)}
	t.Setenv("ELXRAY_POLICY_STATE",path)
	m,err:=New(context.Background(),&Config{})
	if err!=nil {t.Fatal(err)}
	profile,other:=uuid.New(),uuid.New()
	m.RegisterVLESSProfile(profile);m.RegisterVLESSProfile(other)
	flowEnded:=make(chan struct{})
	stopRequested:=make(chan struct{})
	untrack,err:=m.TrackVLESSProfile(profile,func(){close(stopRequested)})
	if err!=nil {t.Fatal(err)}
	defer untrack()
	otherUntrack,err:=m.TrackVLESSProfile(other,func(){t.Error("other device closed")})
	if err!=nil {t.Fatal(err)}
	defer otherUntrack()
	incarnation:=uuid.UUID(m.usageIncarnation)
	req:=feature.ProfileDrainRequest{OwnerID:uuid.New(),ProfileID:profile,
		NodeID:uuid.New(),Incarnation:incarnation,Generation:5}
	result:=make(chan []byte,1)
	go func(){sig,err:=m.DrainVLESSProfile(context.Background(),req);if err!=nil {t.Error(err)};result<-sig}()
	select {case <-stopRequested:case <-time.After(time.Second):t.Fatal("flow stop not requested")}
	if _,err:=m.TrackVLESSProfile(profile,func(){});!errors.Is(err,sessionfence.ErrDenied) {
		t.Fatal("deny admission gate bypassed:",err)
	}
	if _,err:=m.TrackVLESSProfile(other,func(){});err!=nil {t.Fatal("other profile blocked",err)}
	select {case <-result:t.Fatal("drain signed before flow exited");default:}
	untrack();close(flowEnded)
	select {
	case sig:=<-result:
		if len(sig)!=ed25519.SignatureSize {t.Fatal("no core proof")}
		message:=append([]byte("elx-session-fence-v2\x00"),req.OwnerID[:]...)
		// Verify via independently assembled transcript with exact Control wire order.
		message=binary.BigEndian.AppendUint64(message,uint64(req.Generation))
		message=append(message,req.NodeID[:]...)
		message=append(message,req.Incarnation[:]...)
		message=append(message,req.ProfileID[:]...)
		if !ed25519.Verify(pub,message,sig) {t.Fatal("profile fence signature invalid")}
	case <-time.After(time.Second):t.Fatal("wait did not finish")
	}
	otherUntrack()
	if err:=m.Close();err!=nil {t.Fatal(err)}
	m,err=New(context.Background(),&Config{})
	if err!=nil {t.Fatal(err)}
	defer m.Close()
	m.RegisterVLESSProfile(profile)
	m.RegisterVLESSProfile(other)
	if _,err:=m.TrackVLESSProfile(profile,func(){});!errors.Is(err,sessionfence.ErrDenied) {
		t.Fatal("durable fence admission reopened after restart",err)
	}
	if _,err:=m.TrackVLESSProfile(other,func(){});err!=nil {t.Fatal("other account damaged after restart",err)}
}

func TestDrainRejectsUnknownOrNonDurableCore(t *testing.T) {
	t.Setenv("ELXRAY_POLICY_STATE","")
	m,err:=New(context.Background(),&Config{})
	if err!=nil {t.Fatal(err)}
	id:=uuid.New()
	m.RegisterVLESSProfile(id)
	_,err=m.DrainVLESSProfile(context.Background(),feature.ProfileDrainRequest{
		OwnerID:uuid.New(),ProfileID:id,NodeID:uuid.New(),Incarnation:uuid.New(),Generation:1})
	if err==nil {t.Fatal("core issued signature with no durable store")}
}
