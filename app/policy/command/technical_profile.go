package command

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/xtls/xray-core/common/elxjournal"
	"github.com/xtls/xray-core/common/elxprovision"
	"github.com/xtls/xray-core/features/policy"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const technicalServiceName = "elx.core.v1.TechnicalProfile"

// Intentionally a separate RPC from upstream HandlerService/AddUser. Every
// managed request MUST satisfy the existing Unix SO_PEERCRED identity check,
// the core's pinned Control key, live lease, journal and exact executor.
type technicalProfileService interface {
	prepare(context.Context, *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error)
	install(context.Context, *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error)
	installedProof(context.Context, *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error)
	retire(context.Context, *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error)
	retiredProof(context.Context, *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error)
	readback(context.Context, *wrapperspb.StringValue) (*wrapperspb.BytesValue, error)
}

type technicalProfileServer struct {
	manager policy.SubscriptionController
}

func technicalError(err error) error {
	switch {
	case errors.Is(err, elxprovision.ErrInvalid), errors.Is(err, elxjournal.ErrInvalid):
		return status.Error(codes.InvalidArgument, "invalid technical profile preparation")
	case errors.Is(err, elxprovision.ErrUnauthorized):
		return status.Error(codes.PermissionDenied, "invalid or untrusted Control profile grant")
	case errors.Is(err, elxjournal.ErrCollision):
		return status.Error(codes.AlreadyExists, "technical profile UUID or operation collision")
	case errors.Is(err, elxjournal.ErrStale), errors.Is(err, elxjournal.ErrUncertain),
		errors.Is(err, elxjournal.ErrCorrupt):
		return status.Error(codes.FailedPrecondition, "technical profile not safe to prepare")
	default:
		return status.Error(codes.FailedPrecondition, "managed technical provisioning unavailable")
	}
}

func (s *technicalProfileServer) prepare(ctx context.Context,
	request *wrapperspb.BytesValue,
) (*wrapperspb.BytesValue, error) {
	if err := checkLocalPeer(ctx); err != nil {
		return nil, err
	}
	if request == nil || len(request.Value) == 0 || len(request.Value) > 4096 {
		return nil, status.Error(codes.InvalidArgument, "missing signed Control profile grant")
	}
	preparer, ok := s.manager.(interface {
		PrepareTechnicalProfile([]byte) (elxjournal.TechnicalProfile, error)
	})
	if !ok {
		return nil, status.Error(codes.FailedPrecondition, "technical profile controller missing")
	}
	record, err := preparer.PrepareTechnicalProfile(request.Value)
	if err != nil {
		return nil, technicalError(err)
	}
	data, err := json.Marshal(record)
	if err != nil {
		return nil, status.Error(codes.Internal, "technical profile readback encoding failed")
	}
	return wrapperspb.Bytes(data), nil
}

// install is an independently signed v2 action. PREPARE cannot mutate
// VLESS users. The response is local non-admitting readback, not a signed
// Control-ready APPLIED receipt.
func (s *technicalProfileServer) install(ctx context.Context,
	request *wrapperspb.BytesValue,
) (*wrapperspb.BytesValue, error) {
	if err := checkLocalPeer(ctx); err != nil {
		return nil, err
	}
	if request == nil || len(request.Value) == 0 || len(request.Value) > 4096 {
		return nil, status.Error(codes.InvalidArgument, "missing signed Control install grant")
	}
	installer, ok := s.manager.(interface {
		InstallTechnicalProfile([]byte) (elxjournal.TechnicalProfile, error)
	})
	if !ok {
		return nil, status.Error(codes.FailedPrecondition, "technical install controller missing")
	}
	record, err := installer.InstallTechnicalProfile(request.Value)
	if err != nil {
		return nil, technicalError(err)
	}
	data, err := json.Marshal(record)
	if err != nil {
		return nil, status.Error(codes.Internal, "technical installation readback encoding failed")
	}
	return wrapperspb.Bytes(data), nil
}

// installedProof never accepts an agent-authored receipt; the running core
// verifies Control's INSTALL job, live VLESS registration and durable store
// before signing a node/executor/boot-scoped proof with its own private key.
// retire is a separately signed v2 control-plane mutation. It never frees
// a device/owner slot; the core permanently fences the effective VLESS UUID
// before deleting a live user, with crash-uncertain RETIRING quarantine.
func (s *technicalProfileServer) retire(ctx context.Context,
	request *wrapperspb.BytesValue,
) (*wrapperspb.BytesValue, error) {
	if err := checkLocalPeer(ctx); err != nil {
		return nil, err
	}
	if request == nil || len(request.Value) == 0 || len(request.Value) > 4096 {
		return nil, status.Error(codes.InvalidArgument, "missing signed Control retire job")
	}
	retirer, ok := s.manager.(interface {
		RetireTechnicalProfile([]byte) (elxjournal.TechnicalProfile, error)
	})
	if !ok {
		return nil, status.Error(codes.FailedPrecondition, "technical retire controller unavailable")
	}
	record, err := retirer.RetireTechnicalProfile(request.Value)
	if err != nil {
		return nil, technicalError(err)
	}
	data, err := json.Marshal(record)
	if err != nil {
		return nil, status.Error(codes.Internal, "technical retire readback encoding failed")
	}
	return wrapperspb.Bytes(data), nil
}

// retiredProof is the core's independent Ed25519 attestation for a durable
// tombstone plus complete live VLESS UUID absence. A local agent may relay the
// proof, but cannot assert Control APPLIED without PostgreSQL verification.
func (s *technicalProfileServer) retiredProof(ctx context.Context,
	request *wrapperspb.BytesValue,
) (*wrapperspb.BytesValue, error) {
	if err := checkLocalPeer(ctx); err != nil {
		return nil, err
	}
	if request == nil || len(request.Value) == 0 || len(request.Value) > 4096 {
		return nil, status.Error(codes.InvalidArgument, "missing signed Control RETIRE job")
	}
	signer, ok := s.manager.(interface {
		SignedTechnicalRetireReceipt([]byte) (elxprovision.RetireReceipt, error)
	})
	if !ok {
		return nil, status.Error(codes.FailedPrecondition, "core technical RETIRE attestation unavailable")
	}
	proof, err := signer.SignedTechnicalRetireReceipt(request.Value)
	if err != nil {
		return nil, technicalError(err)
	}
	payload, err := json.Marshal(proof)
	if err != nil {
		return nil, status.Error(codes.Internal, "retired proof encoding failed")
	}
	return wrapperspb.Bytes(payload), nil
}

func (s *technicalProfileServer) installedProof(ctx context.Context,
	request *wrapperspb.BytesValue,
) (*wrapperspb.BytesValue, error) {
	if err := checkLocalPeer(ctx); err != nil {
		return nil, err
	}
	if request == nil || len(request.Value) == 0 || len(request.Value) > 4096 {
		return nil, status.Error(codes.InvalidArgument, "missing signed Control installation job")
	}
	signer, ok := s.manager.(interface {
		SignedTechnicalInstallReceipt([]byte) (elxprovision.InstallReceipt, error)
	})
	if !ok {
		return nil, status.Error(codes.FailedPrecondition, "core technical attestation unavailable")
	}
	proof, err := signer.SignedTechnicalInstallReceipt(request.Value)
	if err != nil {
		return nil, technicalError(err)
	}
	data, err := json.Marshal(proof)
	if err != nil {
		return nil, status.Error(codes.Internal, "core installed proof encoding failed")
	}
	return wrapperspb.Bytes(data), nil
}

func (s *technicalProfileServer) readback(ctx context.Context,
	request *wrapperspb.StringValue,
) (*wrapperspb.BytesValue, error) {
	if err := checkLocalPeer(ctx); err != nil {
		return nil, err
	}
	if request == nil {
		return nil, status.Error(codes.InvalidArgument, "missing profile UUID")
	}
	reader, ok := s.manager.(interface {
		TechnicalProfileReadback(string) (elxjournal.TechnicalProfile, error)
	})
	if !ok {
		return nil, status.Error(codes.FailedPrecondition, "technical profile controller missing")
	}
	profile, err := reader.TechnicalProfileReadback(request.Value)
	if err != nil {
		return nil, technicalError(err)
	}
	data, err := json.Marshal(profile)
	if err != nil {
		return nil, status.Error(codes.Internal, "technical profile readback encoding failed")
	}
	return wrapperspb.Bytes(data), nil
}

func technicalHandler[Request, Response any](
	method string,
	call func(*technicalProfileServer, context.Context, *Request) (*Response, error),
) grpc.MethodHandler {
	return func(service any, ctx context.Context, decode func(any) error,
		interceptor grpc.UnaryServerInterceptor,
	) (any, error) {
		request := new(Request)
		if err := decode(request); err != nil {
			return nil, err
		}
		if interceptor == nil {
			return call(service.(*technicalProfileServer), ctx, request)
		}
		return interceptor(ctx, request, &grpc.UnaryServerInfo{
			Server: service, FullMethod: "/" + technicalServiceName + "/" + method,
		}, func(ctx context.Context, req any) (any, error) {
			return call(service.(*technicalProfileServer), ctx, req.(*Request))
		})
	}
}

func registerTechnicalProfile(server *grpc.Server, manager policy.SubscriptionController) {
	server.RegisterService(&grpc.ServiceDesc{
		ServiceName: technicalServiceName,
		HandlerType: (*technicalProfileService)(nil),
		Methods: []grpc.MethodDesc{
			{MethodName: "Prepare", Handler: technicalHandler("Prepare", (*technicalProfileServer).prepare)},
			{MethodName: "Install", Handler: technicalHandler("Install", (*technicalProfileServer).install)},
			{MethodName: "InstalledProof", Handler: technicalHandler("InstalledProof", (*technicalProfileServer).installedProof)},
			{MethodName: "Retire", Handler: technicalHandler("Retire", (*technicalProfileServer).retire)},
			{MethodName: "RetiredProof", Handler: technicalHandler("RetiredProof", (*technicalProfileServer).retiredProof)},
			{MethodName: "Readback", Handler: technicalHandler("Readback", (*technicalProfileServer).readback)},
		},
	}, &technicalProfileServer{manager: manager})
}
