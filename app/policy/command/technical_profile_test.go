package command

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/elxjournal"
	"github.com/xtls/xray-core/common/elxprovision"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestTechnicalProfileRPCRequiresAuthenticatedLocalPeer(t *testing.T) {
	t.Setenv("ELXRAY_MODE", "managed")
	s := &technicalProfileServer{}
	ctx := context.Background()
	if _, err := s.prepare(ctx, wrapperspb.Bytes([]byte("{}"))); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unsigned remote profile preparation must fail before parsing: %v", err)
	}
	if _, err := s.readback(ctx, wrapperspb.String("00000000-0000-0000-0000-000000000001")); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("remote profile readback must require Unix peercred: %v", err)
	}
}

func TestTechnicalProfileErrorsCannotMasqueradeAsAppliedReceipt(t *testing.T) {
	for _, test := range []struct {
		err  error
		code codes.Code
	}{
		{elxprovision.ErrInvalid, codes.InvalidArgument},
		{elxprovision.ErrUnauthorized, codes.PermissionDenied},
		{elxjournal.ErrCollision, codes.AlreadyExists},
		{elxjournal.ErrStale, codes.FailedPrecondition},
		{elxjournal.ErrUncertain, codes.FailedPrecondition},
		{elxjournal.ErrCorrupt, codes.FailedPrecondition},
	} {
		if got := status.Code(technicalError(test.err)); got != test.code {
			t.Fatalf("technical profile failure mapped to %s instead of %s", got, test.code)
		}
	}
}
