package command

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestManagedGenericUserAndHandlerMutationDeniedBeforeAnyApply(t *testing.T) {
	t.Setenv("ELXRAY_MODE", "managed")
	if status.Code(rejectGenericManagedMutation()) != codes.PermissionDenied {
		t.Fatal("managed legacy HandlerService mutation was not denied")
	}
	ctx := context.Background()
	handler := new(handlerServer)
	denied := []struct {
		name string
		run  func() error
	}{
		{"add-user", func() error { return new(AddUserOperation).ApplyInbound(ctx, nil) }},
		{"remove-user", func() error { return new(RemoveUserOperation).ApplyInbound(ctx, nil) }},
		{"add-inbound", func() error { _, err := handler.AddInbound(ctx, nil); return err }},
		{"remove-inbound", func() error { _, err := handler.RemoveInbound(ctx, nil); return err }},
		{"alter-inbound", func() error { _, err := handler.AlterInbound(ctx, nil); return err }},
		{"add-outbound", func() error { _, err := handler.AddOutbound(ctx, nil); return err }},
		{"remove-outbound", func() error { _, err := handler.RemoveOutbound(ctx, nil); return err }},
		{"alter-outbound", func() error { _, err := handler.AlterOutbound(ctx, nil); return err }},
	}
	for _, scenario := range denied {
		t.Run(scenario.name, func(t *testing.T) {
			if got := status.Code(scenario.run()); got != codes.PermissionDenied {
				t.Fatalf("generic mutation bypassed managed deny: %s", got)
			}
		})
	}
}

func TestStandaloneLegacyHandlerMutationsNotGloballyDenied(t *testing.T) {
	t.Setenv("ELXRAY_MODE", "standalone")
	if err := rejectGenericManagedMutation(); err != nil {
		t.Fatalf("standalone upstream-compatible handler API was blocked: %v", err)
	}
}
