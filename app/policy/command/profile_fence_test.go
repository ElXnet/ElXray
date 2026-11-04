//go:build linux

package command

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	apppolicy "github.com/xtls/xray-core/app/policy"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestProfileFenceRPCSignsOnlyDurableAuthenticatedProfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	pub, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{\"Version\":1}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".key", []byte(hex.EncodeToString(key.Seed())), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ELXRAY_POLICY_STATE", path)
	m, err := apppolicy.New(context.Background(), &apppolicy.Config{
		Subscriptions: map[string]*apppolicy.SubscriptionPolicy{
			"account": {Emails: []string{"vless-email"}, UplinkBps: 100, DownlinkBps: 100},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	usage, err := m.SignedUsage("account", "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	var incarnation uuid.UUID
	copy(incarnation[:], usage[:16])
	profile, owner, node := uuid.New(), uuid.New(), uuid.New()
	m.RegisterVLESSProfile(profile)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	(&service{manager: m}).Register(srv)
	go srv.Serve(lis)
	t.Cleanup(func() { srv.Stop(); lis.Close() })
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	call := func(profileID, boot uuid.UUID) ([]byte, error) {
		request := drainInput{OwnerID: owner.String(), ProfileID: profileID.String(),
			NodeID: node.String(), Incarnation: boot.String(), Generation: 7}
		data, err := json.Marshal(request)
		if err != nil {
			return nil, err
		}
		var answer wrapperspb.BytesValue
		err = conn.Invoke(ctx, "/"+profileFenceService+"/Drain", wrapperspb.Bytes(data), &answer)
		return answer.Value, err
	}
	if _, err := call(uuid.New(), incarnation); err == nil {
		t.Fatal("unknown VLESS profile was drained")
	}
	if _, err := call(profile, uuid.New()); err == nil {
		t.Fatal("wrong core incarnation was signed")
	}
	signature, err := call(profile, incarnation)
	if err != nil {
		t.Fatal(err)
	}
	if len(signature) != ed25519.SignatureSize {
		t.Fatal("missing Ed25519 receipt")
	}
	transcript := append([]byte("elx-session-fence-v2\x00"), owner[:]...)
	transcript = binary.BigEndian.AppendUint64(transcript, 7)
	transcript = append(transcript, node[:]...)
	transcript = append(transcript, incarnation[:]...)
	transcript = append(transcript, profile[:]...)
	if !ed25519.Verify(pub, transcript, signature) {
		t.Fatal("core signature does not match Control session fence v2")
	}
	repeated, err := call(profile, incarnation)
	if err != nil || !ed25519.Verify(pub, transcript, repeated) {
		t.Fatal("same fence retry failed", err)
	}
	if _, err := m.TrackVLESSProfile(profile, func() {}); err == nil {
		t.Fatal("drained profile reconnected")
	}
}

func TestProfileFenceRejectsMalformedIdentityAndRemoteRPC(t *testing.T) {
	for _, data := range [][]byte{nil, []byte("{}"), []byte("{"),
		[]byte(`{"OwnerID":"bad","ProfileID":"bad","NodeID":"bad","Incarnation":"bad","Generation":1}`)} {
		if _, err := parseDrainInput(data); err == nil {
			t.Fatalf("accepted bad drain request %q", data)
		}
	}
}
