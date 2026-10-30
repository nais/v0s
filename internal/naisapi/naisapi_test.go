package naisapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/nais/v0s"
	"github.com/nais/v0s/internal/naisapi"
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

// serve returns a Nais API answering every query with response, checking the API key.
func serve(t *testing.T, status int, response string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer secret" {
			t.Errorf("Authorization = %q, want the API key", got)
		}
		var req struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !strings.Contains(req.Query, "environments") {
			t.Errorf("request is not an environments query: %v", err)
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, response)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func newInventory(url string, resolver naisapi.Resolver) *naisapi.Inventory {
	return naisapi.New(url, "secret", http.DefaultClient, resolver, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func environments(envs ...string) string {
	return `{"data":{"environments":{"nodes":[` + strings.Join(envs, ",") + `]}}}`
}

func env(name string, workloads ...string) string {
	return `{"name":"` + name + `","workloads":{"pageInfo":{"hasNextPage":false},"nodes":[` + strings.Join(workloads, ",") + `]}}`
}

func workload(kind, team, name, image, tag, digest string) string {
	d := "null"
	if digest != "" {
		d = `"` + digest + `"`
	}
	return `{"__typename":"` + kind + `","name":"` + name + `","team":{"slug":"` + team + `"},"image":{"name":"` + image + `","tag":"` + tag + `","digest":` + d + `}}`
}

func TestSnapshot(t *testing.T) {
	url := serve(t, http.StatusOK, environments(
		env("dev",
			workload("Application", "team", "pinned", "europe-north1-docker.pkg.dev/p/team/pinned", "1", digestA),
			workload("Job", "team", "tagged", "ghcr.io/nais/tagged", "2026-10-30", ""),
			workload("Application", "team", "hub", "redis", "7", ""),
			workload("Application", "team", "broken", "", "", ""),
		),
		env("prod"),
	))
	resolver := &fakeResolver{digests: map[string]string{
		"ghcr.io/nais/tagged:2026-10-30":  digestB,
		"index.docker.io/library/redis:7": digestC,
	}}

	got, err := newInventory(url, resolver).Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	want := map[string][]v0s.WorkloadImage{
		"dev": {
			{Cluster: "dev", Namespace: "team", Workload: "pinned", Container: "pinned", OwnerKind: "Application", ImageName: "europe-north1-docker.pkg.dev/p/team/pinned", Digest: digestA},
			{Cluster: "dev", Namespace: "team", Workload: "tagged", Container: "tagged", OwnerKind: "Job", ImageName: "ghcr.io/nais/tagged", Digest: digestB},
			{Cluster: "dev", Namespace: "team", Workload: "hub", Container: "hub", OwnerKind: "Application", ImageName: "docker.io/library/redis", Digest: digestC},
		},
		"prod": {}, // known and empty: its stored workloads are to be removed
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Snapshot =\n%+v\nwant\n%+v", got, want)
	}
	if slices.Contains(resolver.calls, "europe-north1-docker.pkg.dev/p/team/pinned:1") {
		t.Error("resolved a tag although Nais API gave the digest")
	}
}

func TestSnapshotIncomplete(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		response string
	}{
		{name: "GraphQL error", status: http.StatusOK, response: `{"errors":[{"message":"unauthorized"}],"data":null}`},
		{name: "partial data", status: http.StatusOK, response: `{"errors":[{"message":"timeout"}],"data":{"environments":{"nodes":[` + env("dev") + `]}}}`},
		{name: "HTTP error", status: http.StatusServiceUnavailable, response: `not ready`},
		{name: "truncated environment", status: http.StatusOK, response: strings.Replace(environments(env("dev")), `"hasNextPage":false`, `"hasNextPage":true`, 1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newInventory(serve(t, tt.status, tt.response), &fakeResolver{}).Snapshot(context.Background())
			if err == nil {
				t.Errorf("Snapshot = %v, want an error", got)
			}
		})
	}
}

func TestTagResolution(t *testing.T) {
	url := serve(t, http.StatusOK, environments(env("dev",
		workload("Application", "team", "app", "ghcr.io/nais/app", "latest", ""),
	)))
	resolver := &fakeResolver{digests: map[string]string{"ghcr.io/nais/app:latest": digestA}}
	inv := newInventory(url, resolver)
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

	fresh := newInventory(url, resolver)
	got, err := fresh.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got["dev"]) != 0 {
		t.Errorf("never resolved: got %+v, want the workload left out", got["dev"])
	}
}
