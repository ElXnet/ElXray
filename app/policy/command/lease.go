package command

import (
	"context"
	"encoding/json"

	apppolicy "github.com/xtls/xray-core/app/policy"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const leaseService = "xray.app.policy.command.ControlLease"

type leaseReceiver struct {
	manager interface {
		RenewControlLease(apppolicy.ControlLease) error
	}
}
type leaseInterface interface {
	renew(context.Context, *wrapperspb.BytesValue) (*emptypb.Empty, error)
}

func (r *leaseReceiver) renew(ctx context.Context, raw *wrapperspb.BytesValue) (*emptypb.Empty, error) {
	if err := checkLocalPeer(ctx); err != nil {
		return nil, err
	}
	if len(raw.GetValue()) == 0 || len(raw.GetValue()) > 2048 {
		return nil, status.Error(codes.InvalidArgument, "invalid Control lease")
	}
	var lease apppolicy.ControlLease
	if json.Unmarshal(raw.GetValue(), &lease) != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid signed Control lease")
	}
	if err := r.manager.RenewControlLease(lease); err != nil {
		return nil, status.Error(codes.PermissionDenied, "Control lease signature, node or expiry invalid")
	}
	return &emptypb.Empty{}, nil
}

func registerControlLease(server *grpc.Server, manager any) {
	verifier, ok := manager.(interface {
		RenewControlLease(apppolicy.ControlLease) error
	})
	if !ok {
		return
	}
	server.RegisterService(&grpc.ServiceDesc{
		ServiceName: leaseService, HandlerType: (*leaseInterface)(nil),
		Methods: []grpc.MethodDesc{{MethodName: "Renew", Handler: func(s any, ctx context.Context,
			decode func(any) error, intercept grpc.UnaryServerInterceptor,
		) (any, error) {
			raw := new(wrapperspb.BytesValue)
			if err := decode(raw); err != nil {
				return nil, err
			}
			if intercept == nil {
				return s.(*leaseReceiver).renew(ctx, raw)
			}
			return intercept(ctx, raw, &grpc.UnaryServerInfo{
				Server:     s,
				FullMethod: "/" + leaseService + "/Renew",
			},
				func(ctx context.Context, in any) (any, error) {
					return s.(*leaseReceiver).renew(ctx, in.(*wrapperspb.BytesValue))
				})
		}}},
	}, &leaseReceiver{manager: verifier})
}
