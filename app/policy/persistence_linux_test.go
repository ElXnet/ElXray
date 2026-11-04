package policy

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/xtls/xray-core/common/subscriptionrate"
)

func TestDurablePolicyRestore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{
		path: `{"Version":1}`, path + ".key": hex.EncodeToString(key.Seed()),
	} {
		if err := os.WriteFile(name, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("ELXRAY_POLICY_STATE", path)
	cfg := &Config{RequireSubscription: true, Subscriptions: map[string]*SubscriptionPolicy{
		"lab": {Emails: []string{"lab"}, UplinkBps: 300, DownlinkBps: 400},
	}}
	m, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(context.Background(), cfg); err == nil {
		t.Fatal("two writers opened one state file")
	}
	update := subscriptionrate.Update{ID: "lab", ExpectedRevision: 1, Revision: 2, UplinkBps: 100, DownlinkBps: 200, Disabled: true}
	p, err := m.UpdateSubscription(update)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := m.DurablePolicyProof(p, "challenge")
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(key.Public().(ed25519.PublicKey), []byte("elx-policy-v1\n6368616c6c656e6765\n6c6162\n2\n100\n200\ntrue"), proof) {
		t.Fatal("invalid durable receipt")
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	m, err = New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.UpdateSubscription(update)
	if err != nil || got.Revision != 2 || !got.Disabled || got.UplinkBps != 100 || got.DownlinkBps != 200 {
		t.Fatalf("retry after restart returned %+v, %v", got, err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(context.Background(), cfg); err == nil {
		t.Fatal("corrupted state silently reset")
	}
}
