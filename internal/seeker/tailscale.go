package seeker

import (
	"context"
	"fmt"

	"tailscale.com/client/tailscale"
	"tailscale.com/ipn/ipnstate"
)

type StatusClient interface {
	StatusWithoutPeers(context.Context) (*ipnstate.Status, error)
}

type TailscaleResolver struct{ Client StatusClient }

func NewTailscaleResolver() TailscaleResolver {
	return TailscaleResolver{Client: &tailscale.LocalClient{}}
}

// Resolve performs one fresh tailscaled LocalAPI query. It has no cache,
// offline path, environment override, or stale-state grace period.
func (r TailscaleResolver) Resolve(ctx context.Context) (Identity, error) {
	if r.Client == nil {
		return Identity{}, fmt.Errorf("tailscaled LocalAPI client is unavailable")
	}
	status, err := r.Client.StatusWithoutPeers(ctx)
	if err != nil {
		return Identity{}, fmt.Errorf("query current tailscaled identity: %w", err)
	}
	if status == nil || status.BackendState != "Running" || !status.HaveNodeKey || status.CurrentTailnet == nil || status.Self == nil || !status.Self.Online {
		return Identity{}, fmt.Errorf("tailscaled is not authenticated and connected")
	}
	login := ""
	if profile, exists := status.User[status.Self.UserID]; exists {
		login = profile.LoginName
	}
	tags := []string{}
	if status.Self.Tags != nil {
		tags = append(tags, status.Self.Tags.AsSlice()...)
	}
	identity, err := New(login, tags)
	if err != nil {
		return Identity{}, fmt.Errorf("tailscaled current identity is unusable: %w", err)
	}
	identity.NodeID = string(status.Self.ID)
	identity.NodeName = status.Self.DNSName
	return identity, nil
}
