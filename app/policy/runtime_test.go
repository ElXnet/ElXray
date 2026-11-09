package policy

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/subscriptionrate"
)

func TestSubscriptionRuntimeCASAndLastGood(t *testing.T) {
	m, err := New(context.Background(), &Config{Subscriptions: map[string]*SubscriptionPolicy{
		"account": {Emails: []string{"a", "b"}, UplinkBps: 1, Revision: 7},
	}})
	if err != nil {
		t.Fatal(err)
	}
	original := m.ForEmail("a")
	original.Uplink.AllowN(time.Now(), subscriptionrate.Burst)
	u := subscriptionrate.Update{ID: "account", ExpectedRevision: 7, Revision: 8, UplinkBps: 1, DownlinkBps: 5}
	p, err := m.UpdateSubscription(u)
	if err != nil || p.Revision != 8 {
		t.Fatal(p, err)
	}
	p.Emails[0] = "tampered"
	for range 10 {
		if _, err := m.UpdateSubscription(u); err != nil {
			t.Fatal(err)
		}
	}
	if original != m.ForEmail("b") || original.Uplink.AllowN(time.Now(), 1) {
		t.Fatal("update reset/replaced credit")
	}
	for _, bad := range []subscriptionrate.Update{
		{ID: "account", ExpectedRevision: 7, Revision: 8, UplinkBps: 2},
		{ID: "account", ExpectedRevision: 8, Revision: 9, UplinkBps: subscriptionrate.MaxRate + 1},
		{ID: "account", ExpectedRevision: 8, Revision: 8},
		{ID: "account", ExpectedRevision: 0, Revision: 1},
		{ID: "missing", ExpectedRevision: 1, Revision: 2},
	} {
		if _, err := m.UpdateSubscription(bad); err == nil {
			t.Fatal("bad update accepted", bad)
		}
	}
	p, err = m.GetSubscription("account")
	if err != nil || p.Revision != 8 || p.Emails[0] != "a" || p.DownlinkBps != 5 {
		t.Fatal("last good policy mutated", p, err)
	}
	var wg sync.WaitGroup
	successes := make(chan bool, 2)
	for _, speed := range []uint64{10, 20} {
		wg.Go(func() {
			_, err := m.UpdateSubscription(subscriptionrate.Update{ID: "account", ExpectedRevision: 8, Revision: 9, UplinkBps: speed})
			if err != nil && !errors.Is(err, subscriptionrate.ErrConflict) {
				t.Error(err)
			}
			successes <- err == nil
		})
	}
	wg.Wait()
	close(successes)
	count := 0
	for ok := range successes {
		if ok {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("CAS admitted %d competing updates", count)
	}
}

func TestSubscriptionRuntimeConfiguredUnlimitedAndDisabled(t *testing.T) {
	m, err := New(context.Background(), &Config{Subscriptions: map[string]*SubscriptionPolicy{"a": {Emails: []string{"email"}}}})
	if err != nil {
		t.Fatal(err)
	}
	budget := m.ForEmail("email")
	if budget == nil {
		t.Fatal("unlimited managed identity not wrapped")
	}
	_, err = m.UpdateSubscription(subscriptionrate.Update{ID: "a", ExpectedRevision: 1, Revision: 2, Disabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := budget.Downlink.WaitN(context.Background(), 1); !errors.Is(err, subscriptionrate.ErrDisabled) {
		t.Fatal(err)
	}
	_, err = m.UpdateSubscription(subscriptionrate.Update{ID: "a", ExpectedRevision: 2, Revision: 3, UplinkBps: 100})
	if err != nil || budget != m.ForEmail("email") {
		t.Fatal(err)
	}
}

func TestSubscriptionFailClosedAndRestore(t *testing.T) {
	t.Setenv("ELXRAY_MODE", "standalone")
	m, err := New(context.Background(), &Config{RequireSubscription: true, Subscriptions: map[string]*SubscriptionPolicy{
		"a": {Emails: []string{"known"}, UplinkBps: 123, DownlinkBps: 456, Revision: 42, Disabled: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, email := range []string{"", "missing", "known"} {
		if err := m.ForEmail(email).Uplink.WaitN(context.Background(), 1); !errors.Is(err, subscriptionrate.ErrDisabled) {
			t.Fatal("unmanaged/disabled user escaped", email, err)
		}
	}
	p, err := m.GetSubscription("a")
	if err != nil || p.Revision != 42 || !p.Disabled || p.UplinkBps != 123 {
		t.Fatal("persisted policy not restored", p, err)
	}
}
