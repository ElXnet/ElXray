package command

import (
	"context"
	"encoding/json"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"time"

	feature "github.com/xtls/xray-core/features/policy"
)

const rateBarrierService = "xray.app.policy.command.RateBarrier"

type rateBarrierHandler struct {
	core feature.SubscriptionRateBarrier
}
type rateBarrierInterface interface {
	prove(context.Context, *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error)
}

func (r *rateBarrierHandler) prove(ctx context.Context, in *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error) {
	if err := checkLocalPeer(ctx); err != nil {
		return nil, err
	}
	if len(in.GetValue()) == 0 || len(in.GetValue()) > 2048 {
		return nil, status.Error(codes.InvalidArgument, "invalid rate barrier")
	}
	var request feature.RateBarrierRequest
	if json.Unmarshal(in.GetValue(), &request) != nil {
		return nil, status.Error(codes.InvalidArgument, "malformed rate barrier request")
	}
	ctx, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()
	proof, err := r.core.ProveRateBarrier(ctx, request)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "rate reduction not fully applied and drained")
	}
	return wrapperspb.Bytes(proof), nil
}
func registerRateBarrier(g *grpc.Server, manager any) {
	impl, ok := manager.(feature.SubscriptionRateBarrier)
	if !ok {
		return
	}
	g.RegisterService(&grpc.ServiceDesc{
		ServiceName: rateBarrierService, HandlerType: (*rateBarrierInterface)(nil),
		Methods: []grpc.MethodDesc{{MethodName: "Prove", Handler: func(s any, ctx context.Context,
			decode func(any) error, intercept grpc.UnaryServerInterceptor) (any, error) {
			input := new(wrapperspb.BytesValue)
			if err := decode(input); err != nil {
				return nil, err
			}
			if intercept == nil {
				return s.(*rateBarrierHandler).prove(ctx, input)
			}
			return intercept(ctx, input, &grpc.UnaryServerInfo{Server: s,
				FullMethod: "/" + rateBarrierService + "/Prove"},
				func(ctx context.Context, in any) (any, error) {
					return s.(*rateBarrierHandler).prove(ctx, in.(*wrapperspb.BytesValue))
				})
		}}},
	}, &rateBarrierHandler{core: impl})
}
