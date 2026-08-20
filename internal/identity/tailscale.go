package identity

import (
	"context"
	"fmt"

	"github.com/marksisson/sphinx/internal/policy"
	"tailscale.com/client/tailscale"
)

type Resolver interface {
	Resolve(context.Context, string) (policy.Principal, error)
}

type TailscaleResolver struct {
	client *tailscale.LocalClient
}

func NewTailscaleResolver() *TailscaleResolver {
	return &TailscaleResolver{client: &tailscale.LocalClient{}}
}

func (r *TailscaleResolver) Resolve(ctx context.Context, remoteAddress string) (policy.Principal, error) {
	who, err := r.client.WhoIs(ctx, remoteAddress)
	if err != nil {
		return policy.Principal{}, fmt.Errorf("resolve Tailscale identity: %w", err)
	}
	if who.UserProfile == nil || who.Node == nil {
		return policy.Principal{}, fmt.Errorf("Tailscale returned an incomplete identity")
	}
	return policy.Principal{
		Login: who.UserProfile.LoginName,
		Node:  who.Node.Name,
		Tags:  append([]string(nil), who.Node.Tags...),
	}, nil
}
