package command

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/features/policy"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const profileFenceService = "xray.app.policy.command.ProfileFence"

type drainInput struct {
	OwnerID     string
	ProfileID   string
	NodeID      string
	Incarnation string
	Generation  int64
}

type (
	profileFenceServer    struct{ manager policy.VLESSProfileManager }
	profileFenceInterface interface {
		drain(context.Context, *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error)
	}
)

func parseDrainInput(data []byte) (policy.ProfileDrainRequest, error) {
	var input drainInput
	if len(data) == 0 || len(data) > 1024 || json.Unmarshal(data, &input) != nil ||
		input.Generation <= 0 {
		return policy.ProfileDrainRequest{}, errors.New("invalid profile fence request")
	}
	parts := []string{input.OwnerID, input.ProfileID, input.NodeID, input.Incarnation}
	ids := make([]uuid.UUID, 4)
	for i, raw := range parts {
		id, err := uuid.Parse(raw)
		if err != nil || id == uuid.Nil || id.String() != raw {
			return policy.ProfileDrainRequest{}, errors.New("invalid profile fence UUID")
		}
		ids[i] = id
	}
	return policy.ProfileDrainRequest{
		OwnerID: ids[0], ProfileID: ids[1], NodeID: ids[2],
		Incarnation: ids[3], Generation: input.Generation,
	}, nil
}

func (s *profileFenceServer) drain(ctx context.Context, r *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error) {
	if err := checkLocalPeer(ctx); err != nil {
		return nil, err
	}
	req, err := parseDrainInput(r.GetValue())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid profile fence request")
	}
	// A core-side close may need time for active TCP/Mux/reverse flows to
	// finish. Cancellation never causes a signature for undrained flows.
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	proof, err := s.manager.DrainVLESSProfile(ctx, req)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "VLESS profile not yet durably drained")
	}
	return wrapperspb.Bytes(proof), nil
}

func registerProfileFence(server *grpc.Server, manager policy.SubscriptionController) {
	drainer, ok := manager.(policy.VLESSProfileManager)
	if !ok {
		return
	}
	server.RegisterService(&grpc.ServiceDesc{
		ServiceName: profileFenceService, HandlerType: (*profileFenceInterface)(nil),
		Methods: []grpc.MethodDesc{{MethodName: "Drain", Handler: func(s any, ctx context.Context,
			decode func(any) error, intercept grpc.UnaryServerInterceptor,
		) (any, error) {
			input := new(wrapperspb.BytesValue)
			if err := decode(input); err != nil {
				return nil, err
			}
			if intercept == nil {
				return s.(*profileFenceServer).drain(ctx, input)
			}
			return intercept(ctx, input, &grpc.UnaryServerInfo{
				Server: s, FullMethod: "/" + profileFenceService + "/Drain",
			}, func(ctx context.Context, r any) (any, error) {
				return s.(*profileFenceServer).drain(ctx, r.(*wrapperspb.BytesValue))
			})
		}}},
	}, &profileFenceServer{manager: drainer})
}
