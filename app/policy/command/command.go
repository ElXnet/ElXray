package command

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"strconv"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/elxsecurity"
	"github.com/xtls/xray-core/common/elxjournal"
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

func (s *service) Register(server *grpc.Server) {
	RegisterSubscriptionServiceServer(server, s)
	registerProfileFence(server, s.manager)
	registerControlLease(server, s.manager)
	registerRateBarrier(server, s.manager)
}

// The standard Commander transport has no authentication. Refuse remote peers
// even if someone accidentally exposes its listener. Remote agents use SSH/WG
// to a local authenticated supervisor; WireGuard IP alone is not an API credential.
func checkLocalPeer(ctx context.Context) error {
	p, ok := peer.FromContext(ctx)
	if elxsecurity.Managed() {
		uid, gid, err := elxsecurity.AgentIdentity()
		if err != nil || !ok || p == nil {
			return status.Error(codes.PermissionDenied, "managed Commander requires authenticated agent identity")
		}
		if _, isUnix := p.Addr.(*net.UnixAddr); !isUnix {
			return status.Error(codes.PermissionDenied, "managed Commander rejects TCP and forwarded connections")
		}
		identity, verified := p.AuthInfo.(elxsecurity.UnixPeerInfo)
		if !verified || identity.UID != uid || identity.GID != gid || identity.PID <= 0 {
			return status.Error(codes.PermissionDenied, "managed Commander requires kernel-verified agent credentials")
		}
		return nil
	}
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
	case errors.Is(err, elxjournal.ErrCollision):
		return status.Error(codes.AlreadyExists, err.Error())
	case errors.Is(err, elxjournal.ErrUncertain):
		return status.Error(codes.Unavailable, err.Error())
	case errors.Is(err, elxjournal.ErrStale):
		return status.Error(codes.Aborted, err.Error())
	case errors.Is(err, elxjournal.ErrInvalid):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, elxjournal.ErrCorrupt):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, subscriptionrate.ErrConflict):
		return status.Error(codes.Aborted, err.Error())
	case errors.Is(err, subscriptionrate.ErrUnauthorized):
		return status.Error(codes.PermissionDenied, err.Error())
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
		if nonceRequested := md.Get("elx-store-witness-nonce"); len(nonceRequested) != 0 {
			if len(nonceRequested) != 1 || nonceRequested[0] != "1" {
				return nil, status.Error(codes.InvalidArgument, "invalid independent store witness nonce request")
			}
			manager, valid := s.manager.(interface {
				ManagedWitnessNonce(string) (string, error)
			})
			if !valid {
				return nil, status.Error(codes.FailedPrecondition, "core store witness unavailable")
			}
			nonce, err := manager.ManagedWitnessNonce(p.ID)
			if err != nil { return nil, status.Error(codes.FailedPrecondition, "durable store not ready") }
			if err := grpc.SetHeader(ctx, metadata.Pairs("elx-store-witness-nonce", nonce)); err != nil {
				return nil, err
			}
		}
		if challenge := md.Get("elx-lease-accept-challenge"); len(challenge) != 0 {
			if len(challenge) != 1 || len(challenge[0]) != 32 {
				return nil, status.Error(codes.InvalidArgument, "invalid lease acceptance challenge")
			}
			signer, ok := s.manager.(interface {
				SignedLeaseAcceptance(string, string) ([]byte, error)
			})
			if !ok {
				return nil, status.Error(codes.FailedPrecondition, "signed lease acceptance unavailable")
			}
			proof, err := signer.SignedLeaseAcceptance(p.ID, challenge[0])
			if err != nil {
				return nil, status.Error(codes.FailedPrecondition, "live core lease not accepted")
			}
			if err := grpc.SetHeader(ctx, metadata.Pairs("elx-lease-accept-bin", string(proof))); err != nil {
				return nil, err
			}
		}
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
		if challenge := md.Get("elx-pressure-challenge"); len(challenge) != 0 {
			if len(challenge) != 1 || len(challenge[0]) != 32 {
				return nil, status.Error(codes.InvalidArgument, "invalid pressure challenge")
			}
			signer, ok := s.manager.(interface {
				SignedPressure(string, string) ([]byte, error)
			})
			if !ok {
				return nil, status.Error(codes.FailedPrecondition, "signed pressure unavailable")
			}
			sample, err := signer.SignedPressure(p.ID, challenge[0])
			if err != nil {
				return nil, status.Error(codes.FailedPrecondition, "signed pressure unavailable")
			}
			if err := grpc.SetHeader(ctx, metadata.Pairs("elx-pressure-bin", string(sample))); err != nil {
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
		if requested := md.Get("elx-op-readback-id"); len(requested) != 0 {
			challenge := md.Get("elx-op-readback-challenge")
			if len(requested) != 1 || len(challenge) != 1 || len(challenge[0]) != 64 {
				return nil, status.Error(codes.InvalidArgument, "invalid durable operation readback request")
			}
			signer, ok := s.manager.(interface {
				SignedManagedReceipt(string, string, string) ([]byte, error)
			})
			if !ok {
				return nil, status.Error(codes.FailedPrecondition, "managed operation readback unavailable")
			}
			evidence, err := signer.SignedManagedReceipt(p.ID, requested[0], challenge[0])
			if err != nil {
				return nil, status.Error(codes.FailedPrecondition, "managed operation not durably applied")
			}
			if err := grpc.SetHeader(ctx, metadata.Pairs("elx-operation-receipt-bin", string(evidence))); err != nil {
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
	// Standalone compatibility permits local CLI, but never unlimited runtime rates. Unlimited rates must be set
	// through the administrator-owned startup configuration.
	if r.GetUplinkBps() == 0 || r.GetDownlinkBps() == 0 {
		return nil, status.Error(codes.PermissionDenied, "unlimited rates require administrator configuration")
	}
	update := subscriptionrate.Update{ID: r.Id, ExpectedRevision: r.ExpectedRevision, Revision: r.Revision,
		UplinkBps: r.GetUplinkBps(), DownlinkBps: r.GetDownlinkBps(), Disabled: r.GetDisabled()}
	// The old RPC path remains only for standalone or explicitly pre-migration
	// managed nodes. Once the durable journal is active, a mutation MUST carry
	// exact Control operation identity through the authenticated local channel.
	var p subscriptionrate.Policy
	var err error
	md, hasMetadata := metadata.FromIncomingContext(ctx)
	hasOperation := hasMetadata && len(md.Get("elx-op-id")) != 0
	if hasOperation {
		get := func(k string) (string, bool) {
			v := md.Get(k)
			returnValue := ""
			if len(v) == 1 { returnValue = v[0] }
			return returnValue, len(v) == 1 && returnValue != ""
		}
		id, okID := get("elx-op-id")
		node, okNode := get("elx-op-node")
		resource, okResource := get("elx-op-resource")
		executor, okExecutor := get("elx-op-executor")
		hash, okHash := get("elx-op-hash")
		generationRaw, okGeneration := get("elx-op-generation")
		generation, parsed := strconv.ParseUint(generationRaw, 10, 64)
		if !(okID && okNode && okResource && okExecutor && okHash && okGeneration) || parsed != nil {
			return nil, status.Error(codes.InvalidArgument, "invalid managed operation metadata")
		}
		manager, ok := s.manager.(interface {
			UpdateManagedSubscription(subscriptionrate.Update, elxjournal.Command) (subscriptionrate.Policy, error)
		})
		if !ok { return nil, status.Error(codes.FailedPrecondition, "durable managed operation unavailable") }
		p, err = manager.UpdateManagedSubscription(update, elxjournal.Command{
			OperationID: id, NodeID: node, ExecutorID: executor, ResourceID: resource,
			AuthorityGeneration: generation, ExpectedRevision: update.ExpectedRevision,
			NewRevision: update.Revision, PayloadSHA256: hash, Kind: "set-rate",
		})
	} else {
		p, err = s.manager.UpdateSubscription(update)
	}
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
