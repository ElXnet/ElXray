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
			{MethodName: "Readback", Handler: technicalHandler("Readback", (*technicalProfileServer).readback)},
		},
	}, &technicalProfileServer{manager: manager})
}
