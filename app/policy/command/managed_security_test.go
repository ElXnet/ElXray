package command

import (
	"context"
	"net"
	"os"
	"strconv"
	"testing"

	"github.com/xtls/xray-core/common/elxsecurity"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func TestManagedCommanderRejectsForgedLocalPeers(t *testing.T) {
	t.Setenv("ELXRAY_MODE","managed")
	uid:=uint32(os.Geteuid()+42)
	gid:=uint32(65534)
	t.Setenv("ELXRAY_AGENT_UID",strconv.FormatUint(uint64(uid),10))
	t.Setenv("ELXRAY_AGENT_GID",strconv.FormatUint(uint64(gid),10))
	unixAddr:=&net.UnixAddr{Name:"/run/elxray/core.sock",Net:"unix"}
	good:=elxsecurity.UnixPeerInfo{UID:uid,GID:gid,PID:42}
	for _,p:=range []*peer.Peer{
		{Addr:&net.TCPAddr{IP:net.ParseIP("127.0.0.1")},AuthInfo:good},
		{Addr:unixAddr},
		{Addr:unixAddr,AuthInfo:elxsecurity.UnixPeerInfo{UID:uid+1,GID:gid,PID:42}},
		{Addr:unixAddr,AuthInfo:elxsecurity.UnixPeerInfo{UID:uid,GID:gid+1,PID:42}},
		{Addr:unixAddr,AuthInfo:elxsecurity.UnixPeerInfo{UID:uid,GID:gid,PID:0}},
	} {
		if err:=checkLocalPeer(peer.NewContext(context.Background(),p));status.Code(err)!=codes.PermissionDenied {
			t.Fatalf("untrusted managed caller authorized: %#v %v",p,err)
		}
	}
	if err:=checkLocalPeer(peer.NewContext(context.Background(),&peer.Peer{Addr:unixAddr,AuthInfo:good}));err!=nil {
		t.Fatal("verified kernel peer rejected:",err)
	}
}
