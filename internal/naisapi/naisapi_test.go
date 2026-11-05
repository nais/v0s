package naisapi_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"google.golang.org/grpc"

	"github.com/nais/v0s"
	"github.com/nais/v0s/internal/naisapi"
	"github.com/nais/v0s/internal/naisapi/protoapi"
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
	return naisapi.New(client, resolver, slog.New(slog.NewTextHandler(io.Discard, nil)))
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
			{Environment: "dev", Team: "team", Workload: "pinned", ImageName: "europe-north1-docker.pkg.dev/p/team/pinned", Digest: digestA},
			{Environment: "dev", Team: "team", Workload: "tagged", ImageName: "ghcr.io/nais/tagged", Digest: digestB},
			{Environment: "dev", Team: "team", Workload: "hub", ImageName: "docker.io/library/redis", Digest: digestC},
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

func TestSnapshotIncomplete(t *testing.T) {
	tests := map[string]fakeClient{
		"unavailable":              {err: errors.New("connection refused")},
		"environment twice":        environments(env("dev"), env("dev")),
		"environment without name": environments(env("")),
	}
	for name, client := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := newInventory(client, &fakeResolver{}).Snapshot(context.Background())
			if err == nil {
				t.Errorf("Snapshot = %v, want an error", got)
			}
		})
	}
}

func TestTagResolution(t *testing.T) {
	client := environments(env("dev", workload("team", "app", "ghcr.io/nais/app:latest")))
	resolver := &fakeResolver{digests: map[string]string{"ghcr.io/nais/app:latest": digestA}}
	inv := newInventory(client, resolver)
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	inv.SetNow(func() time.Time { return now })

	digest := func() string {
		t.Helper()
		got, err := inv.Snapshot(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(got["dev"]) == 0 {
			return ""
		}
		return got["dev"][0].Digest
	}

	if got := digest(); got != digestA {
		t.Fatalf("first snapshot: digest %q, want %q", got, digestA)
	}

	resolver.digests["ghcr.io/nais/app:latest"] = digestB // the tag moves
	now = now.Add(30 * time.Minute)
	if got := digest(); got != digestA {
		t.Errorf("within the TTL: digest %q, want the cached %q", got, digestA)
	}
	if len(resolver.calls) != 1 {
		t.Errorf("registry asked %d times within the TTL, want once", len(resolver.calls))
	}

	now = now.Add(time.Hour)
	if got := digest(); got != digestB {
		t.Errorf("after the TTL: digest %q, want the moved tag's %q", got, digestB)
	}

	delete(resolver.digests, "ghcr.io/nais/app:latest") // the registry fails
	now = now.Add(2 * time.Hour)
	if got := digest(); got != digestB {
		t.Errorf("registry failing: digest %q, want the last known %q", got, digestB)
	}

	fresh := newInventory(client, resolver)
	got, err := fresh.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got["dev"]) != 0 {
		t.Errorf("never resolved: got %+v, want the workload left out", got["dev"])
	}
}
