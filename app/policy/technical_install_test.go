package policy

import (
	"errors"
	"testing"

	"github.com/xtls/xray-core/common/elxprovision"
)

func TestTechnicalInstallFailsWithoutManagedAuthorityAndDurableJournal(t *testing.T) {
	for name, instance := range map[string]*Instance{
		"standalone":       {technicalProvisioning: false},
		"missing-journal":  {technicalProvisioning: true},
		"nil-runtime":      nil,
	} {
		t.Run(name, func(t *testing.T) {
			var prepared *Instance = instance
			_, err := prepared.InstallTechnicalProfile([]byte(`{"Grant":{"Version":2,"Action":"install"}}`))
			if !errors.Is(err, elxprovision.ErrUnauthorized) {
				t.Fatalf("untrusted technical INSTALL reached live VLESS: %v", err)
			}
		})
	}
}
