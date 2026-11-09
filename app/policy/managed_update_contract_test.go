package policy

import (
	"testing"

	"github.com/xtls/xray-core/common/subscriptionrate"
)

func TestManagedRateMutationCanonicalTranscript(t *testing.T) {
	base := subscriptionrate.Update{ID: "lab", ExpectedRevision: 1, Revision: 2,
		UplinkBps: 90, DownlinkBps: 180, Disabled: false}
	const golden = "4255081ce063d5fc3a34d2099448e626e4202b80197d47d26b200ec2d19193bd"
	if got := ManagedUpdateHash(base); got != golden {
		t.Fatalf("managed update transcript differs from Control: %s", got)
	}
	for _, mutate := range []func(*subscriptionrate.Update){
		func(x *subscriptionrate.Update) { x.ID += "-other" },
		func(x *subscriptionrate.Update) { x.ExpectedRevision++ },
		func(x *subscriptionrate.Update) { x.Revision++ },
		func(x *subscriptionrate.Update) { x.UplinkBps++ },
		func(x *subscriptionrate.Update) { x.DownlinkBps++ },
		func(x *subscriptionrate.Update) { x.Disabled = true },
	} {
		copy := base
		mutate(&copy)
		if ManagedUpdateHash(copy) == golden {
			t.Fatalf("modified managed mutation retained original digest: %+v", copy)
		}
	}
}
