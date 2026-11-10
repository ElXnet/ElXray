package command

import (
	"context"
	"strings"
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
	if _, err := s.install(ctx, wrapperspb.Bytes([]byte("{}"))); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unsigned remote profile installation must fail before parsing: %v", err)
	}
	if _, err := s.installedProof(ctx, wrapperspb.Bytes([]byte("{}"))); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("remote installation proof signing must require authenticated local peer: %v", err)
	}
	if _, err := s.retire(ctx, wrapperspb.Bytes([]byte("{}"))); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unsigned remote VLESS retire must require Unix peercred: %v", err)
	}
	if _, err := s.retiredProof(ctx, wrapperspb.Bytes([]byte("{}"))); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("remote signed VLESS retirement proof must require Unix peercred: %v", err)
	}
	if _, err := s.recoverInstalledProof(ctx, wrapperspb.String("11111111-1111-4111-8111-111111111111/22222222-2222-4222-8222-222222222222")); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("remote installed recovery proof must require Unix peercred: %v", err)
	}
	if _, err := s.recoverRetiredProof(ctx, wrapperspb.String("11111111-1111-4111-8111-111111111111/22222222-2222-4222-8222-222222222222")); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("remote retired recovery proof must require Unix peercred: %v", err)
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

func TestTechnicalRecoverySelectorRejectsAmbiguousAndNonCanonicalOperations(t *testing.T) {
	id := "11111111-1111-4111-8111-111111111111"
	op := "22222222-2222-4222-8222-22222222222a"
	if gotID, gotOp, err := technicalRecoveryIDs(id + "/" + op); err != nil || gotID != id || gotOp != op {
		t.Fatalf("canonical read-only recovery IDs rejected: %q %q %v", gotID, gotOp, err)
	}
	for _, raw := range []string{
		"", id, id + "/" + op + "/extra", id + "/" + id + " ",
		"00000000-0000-0000-0000-000000000000/" + op,
		id + "/00000000-0000-0000-0000-000000000000",
		id + "/" + strings.ToUpper(op),
	} {
		if _, _, err := technicalRecoveryIDs(raw); err == nil {
			t.Fatalf("malformed recovery selector accepted: %q", raw)
		}
	}
}
