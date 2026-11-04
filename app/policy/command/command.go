package command

import (
	"context"
	"encoding/hex"
	"errors"
	"net"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/subscriptionrate"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type service struct {
	UnimplementedSubscriptionServiceServer
	manager policy.SubscriptionController
}

func (s *service) Register(server *grpc.Server) { RegisterSubscriptionServiceServer(server, s) }

// The standard Commander transport has no authentication. Refuse remote peers
// even if someone accidentally exposes its listener. Remote agents use SSH/WG
// to a local authenticated supervisor; WireGuard IP alone is not an API credential.
func checkLocalPeer(ctx context.Context) error {
	p, ok := peer.FromContext(ctx)
	if ok {
		switch a := p.Addr.(type) {
		case *net.TCPAddr:
			if a.IP.IsLoopback() {
				return nil
			}
		case *net.UnixAddr:
			return nil
		}
	}
	return status.Error(codes.PermissionDenied, "subscription API requires a local peer")
}

func response(p subscriptionrate.Policy) *Subscription {
	return &Subscription{Id: p.ID, Emails: p.Emails, UplinkBps: p.UplinkBps, DownlinkBps: p.DownlinkBps, Revision: p.Revision, Disabled: p.Disabled}
}

func rpcError(err error) error {
	switch {
	case errors.Is(err, subscriptionrate.ErrNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, subscriptionrate.ErrConflict):
		return status.Error(codes.Aborted, err.Error())
	case errors.Is(err, subscriptionrate.ErrInvalid):
		return status.Error(codes.InvalidArgument, err.Error())
	default:
		return status.Error(codes.Internal, "subscription operation failed")
	}
}

func (s *service) GetSubscription(ctx context.Context, r *GetSubscriptionRequest) (*Subscription, error) {
	if err := checkLocalPeer(ctx); err != nil {
		return nil, err
	}
	if r == nil || len(r.Id) == 0 || len(r.Id) > 1024 {
		return nil, status.Error(codes.InvalidArgument, "invalid subscription id")
	}
	p, err := s.manager.GetSubscription(r.Id)
	if err != nil {
		return nil, rpcError(err)
	}
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if challenge := md.Get("elx-usage-challenge"); len(challenge) != 0 {
			if len(challenge) != 1 || len(challenge[0]) != 32 {
				return nil, status.Error(codes.InvalidArgument, "invalid usage challenge")
			}
			signer, ok := s.manager.(interface {
				SignedUsage(string, string) ([]byte, error)
			})
			if !ok {
				return nil, status.Error(codes.FailedPrecondition, "usage unavailable")
			}
			sample, err := signer.SignedUsage(p.ID, challenge[0])
			if err != nil {
				return nil, status.Error(codes.FailedPrecondition, "usage unavailable")
			}
			if err := grpc.SetHeader(ctx, metadata.Pairs("elx-usage-bin", string(sample))); err != nil {
				return nil, err
			}
		}
		if challenge := md.Get("elx-policy-challenge"); len(challenge) != 0 {
			if len(challenge) != 1 || len(challenge[0]) < 1 || len(challenge[0]) > 128 {
				return nil, status.Error(codes.InvalidArgument, "invalid policy challenge")
			}
			signer, ok := s.manager.(interface {
				DurablePolicyProof(subscriptionrate.Policy, string) ([]byte, error)
			})
			if !ok {
				return nil, status.Error(codes.FailedPrecondition, "durable policy unavailable")
			}
			proof, err := signer.DurablePolicyProof(p, challenge[0])
			if err != nil {
				return nil, status.Error(codes.FailedPrecondition, "durable policy unavailable")
			}
			if err := grpc.SetHeader(ctx, metadata.Pairs("elx-policy-proof", hex.EncodeToString(proof))); err != nil {
				return nil, err
			}
		}
	}
	return response(p), nil
}

func (s *service) SetSubscription(ctx context.Context, r *SetSubscriptionRequest) (*Subscription, error) {
	if err := checkLocalPeer(ctx); err != nil {
		return nil, err
	}
	if r == nil || r.UplinkBps == nil || r.DownlinkBps == nil || r.Disabled == nil {
		return nil, status.Error(codes.InvalidArgument, "both rates and disabled must be explicit")
	}
	// Commander authenticates locality only. Unlimited rates must be set
	// through the administrator-owned startup configuration.
	if r.GetUplinkBps() == 0 || r.GetDownlinkBps() == 0 {
		return nil, status.Error(codes.PermissionDenied, "unlimited rates require administrator configuration")
	}
	p, err := s.manager.UpdateSubscription(subscriptionrate.Update{ID: r.Id, ExpectedRevision: r.ExpectedRevision, Revision: r.Revision, UplinkBps: r.GetUplinkBps(), DownlinkBps: r.GetDownlinkBps(), Disabled: r.GetDisabled()})
	if err != nil {
		return nil, rpcError(err)
	}
	return response(p), nil
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, cfg interface{}) (interface{}, error) {
		s := new(service)
		if err := core.RequireFeatures(ctx, func(m policy.Manager) error {
			controller, ok := m.(policy.SubscriptionController)
			if !ok {
				return errors.New("policy manager does not implement subscription control")
			}
			s.manager = controller
			return nil
		}); err != nil {
			return nil, err
		}
		return s, nil
	}))
}
