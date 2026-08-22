package seeker

import (
	"context"
	"errors"
	"testing"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
)

type fakeStatusClient struct {
	status *ipnstate.Status
	err    error
	calls  int
}

func (f *fakeStatusClient) StatusWithoutPeers(context.Context) (*ipnstate.Status, error) {
	f.calls++
	return f.status, f.err
}

func runningStatus() *ipnstate.Status {
	id := tailcfg.UserID(42)
	tags := views.SliceOf([]string{"tag:ci"})
	return &ipnstate.Status{BackendState: "Running", HaveNodeKey: true, CurrentTailnet: &ipnstate.TailnetStatus{Name: "example"}, Self: &ipnstate.PeerStatus{UserID: id, Online: true, Tags: &tags}, User: map[tailcfg.UserID]tailcfg.UserProfile{id: {ID: id, LoginName: "alice@example.com"}}}
}

func TestTailscaleResolverLoginAndTags(t *testing.T) {
	client := &fakeStatusClient{status: runningStatus()}
	resolver := TailscaleResolver{Client: client}
	identity, err := resolver.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if identity.Login != "alice@example.com" || len(identity.Tags) != 1 || identity.Tags[0] != "tag:ci" {
		t.Fatalf("identity = %#v", identity)
	}
	if _, err := resolver.Resolve(context.Background()); err != nil {
		t.Fatal(err)
	}
	if client.calls != 2 {
		t.Fatalf("fresh LocalAPI calls = %d", client.calls)
	}
}

func TestTailscaleResolverTagOnlyWithoutProfile(t *testing.T) {
	status := runningStatus()
	status.User = nil
	identity, err := (TailscaleResolver{Client: &fakeStatusClient{status: status}}).Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if identity.Login != "" || len(identity.Tags) != 1 {
		t.Fatalf("tag-only identity = %#v", identity)
	}
}

func TestTailscaleResolverFailsClosed(t *testing.T) {
	for name, status := range map[string]*ipnstate.Status{"missing": nil, "stopped": {BackendState: "Stopped"}, "no self": {BackendState: "Running", HaveNodeKey: true, CurrentTailnet: &ipnstate.TailnetStatus{}}, "neither identity": runningStatus()} {
		t.Run(name, func(t *testing.T) {
			if name == "neither identity" {
				status.User = nil
				status.Self.Tags = nil
			}
			if _, err := (TailscaleResolver{Client: &fakeStatusClient{status: status}}).Resolve(context.Background()); err == nil {
				t.Fatal("unusable tailscaled state accepted")
			}
		})
	}
	client := &fakeStatusClient{err: errors.New("unavailable")}
	if _, err := (TailscaleResolver{Client: client}).Resolve(context.Background()); err == nil {
		t.Fatal("LocalAPI failure accepted")
	}
}
