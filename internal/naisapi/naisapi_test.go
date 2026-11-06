package naisapi_test

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"slices"
	"sync"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"google.golang.org/grpc"

	"github.com/nais/v0s/internal/naisapi"
	"github.com/nais/v0s/internal/naisapi/protoapi"
	"github.com/nais/v0s/internal/v0s"
)

const (
	digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	digestC = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

// fakeResolver maps normalized tag references to digests; a missing tag fails to resolve.
type fakeResolver struct {
	mu      sync.Mutex
	digests map[string]string
	calls   []string
}

func (r *fakeResolver) Digest(_ context.Context, ref name.Tag) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, ref.Name())
	if d, ok := r.digests[ref.Name()]; ok {
		return d, nil
	}
	return "", errors.New("registry unavailable")
}

// fakeClient answers ListImages with resp or err.
type fakeClient struct {
	resp *protoapi.ListWorkloadImagesResponse
	err  error
}

func (c fakeClient) ListImages(context.Context, *protoapi.ListWorkloadImagesRequest, ...grpc.CallOption) (*protoapi.ListWorkloadImagesResponse, error) {
	return c.resp, c.err
}

func newInventory(client protoapi.WorkloadsClient, resolver naisapi.Resolver) *naisapi.Inventory {
	return naisapi.New(client, resolver, slog.New(slog.DiscardHandler))
}

func environments(envs ...*protoapi.EnvironmentWorkloadImages) fakeClient {
	return fakeClient{resp: &protoapi.ListWorkloadImagesResponse{Environments: envs}}
}

func env(name string, workloads ...*protoapi.WorkloadImage) *protoapi.EnvironmentWorkloadImages {
	return &protoapi.EnvironmentWorkloadImages{Environment: name, Workloads: workloads}
}

func workload(team, name, image string) *protoapi.WorkloadImage {
	return &protoapi.WorkloadImage{TeamSlug: team, Name: name, Image: image}
}

func TestSnapshot(t *testing.T) {
	client := environments(
		env("dev",
			workload("team", "pinned", "europe-north1-docker.pkg.dev/p/team/pinned:1@"+digestA),
			workload("team", "tagged", "ghcr.io/nais/tagged:2026-10-30"),
			workload("team", "hub", "redis:7"),
			workload("team", "gone", "ghcr.io/nais/gone:1"),
			workload("team", "broken", ""),
		),
		env("prod"),
	)
	resolver := &fakeResolver{digests: map[string]string{
		"ghcr.io/nais/tagged:2026-10-30":  digestB,
		"index.docker.io/library/redis:7": digestC,
	}}

	got, err := newInventory(client, resolver).Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	want := map[string][]v0s.WorkloadImage{
		"dev": {
			{Environment: "dev", Team: "team", Workload: "pinned", Reference: "europe-north1-docker.pkg.dev/p/team/pinned:1@" + digestA, ImageName: "europe-north1-docker.pkg.dev/p/team/pinned", Digest: digestA},
			{Environment: "dev", Team: "team", Workload: "tagged", Reference: "ghcr.io/nais/tagged:2026-10-30", ImageName: "ghcr.io/nais/tagged", Digest: digestB},
			{Environment: "dev", Team: "team", Workload: "hub", Reference: "redis:7", ImageName: "docker.io/library/redis", Digest: digestC},
			{Environment: "dev", Team: "team", Workload: "gone", Reference: "ghcr.io/nais/gone:1", ResolveError: "resolving ghcr.io/nais/gone:1: registry unavailable"},
			{Environment: "dev", Team: "team", Workload: "broken", ResolveError: "no image"},
		},
		"prod": {}, // known and empty: its stored workloads are to be removed
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Snapshot =\n%+v\nwant\n%+v", got, want)
	}
	if slices.Contains(resolver.calls, "europe-north1-docker.pkg.dev/p/team/pinned:1") {
		t.Error("resolved a tag although the image reference has a digest")
	}
}

func TestSnapshotUnavailable(t *testing.T) {
	client := fakeClient{err: errors.New("connection refused")}
	if got, err := newInventory(client, &fakeResolver{}).Snapshot(context.Background()); err == nil {
		t.Errorf("Snapshot = %v, want an error", got)
	}
}

func TestMovedTagKeepsResolvedDigest(t *testing.T) {
	client := environments(env("dev", workload("team", "app", "ghcr.io/nais/app:latest")))
	resolver := &fakeResolver{digests: map[string]string{"ghcr.io/nais/app:latest": digestA}}
	inv := newInventory(client, resolver)

	for _, registryDigest := range []string{digestA, digestB} {
		resolver.digests["ghcr.io/nais/app:latest"] = registryDigest
		got, err := inv.Snapshot(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(got["dev"]) != 1 || got["dev"][0].Digest != digestA {
			t.Fatalf("Snapshot = %+v, want the originally resolved digest %s", got, digestA)
		}
	}
	if len(resolver.calls) != 1 {
		t.Errorf("registry asked %d times, want once", len(resolver.calls))
	}
}

func TestTagResolution(t *testing.T) {
	client := environments(env("dev", workload("team", "app", "ghcr.io/nais/app:latest")))
	resolver := &fakeResolver{digests: map[string]string{}} // the registry fails
	inv := newInventory(client, resolver)

	digest := func() string {
		t.Helper()
		got, err := inv.Snapshot(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(got["dev"]) != 1 {
			t.Fatalf("Snapshot = %+v, want the workload", got)
		}
		return got["dev"][0].Digest
	}

	if got := digest(); got != "" {
		t.Errorf("registry failing: digest %q, want none", got)
	}
	resolver.digests["ghcr.io/nais/app:latest"] = digestA
	for range 2 {
		if got := digest(); got != digestA {
			t.Errorf("registry back: digest %q, want %q", got, digestA)
		}
	}
	if len(resolver.calls) != 2 {
		t.Errorf("registry asked %d times, want twice: once failing, once more after", len(resolver.calls))
	}
}
