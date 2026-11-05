// Package naisapi lists the images of Nais workloads (applications and jobs) from Nais API's
// internal gRPC API.
package naisapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/nais/v0s"
	"github.com/nais/v0s/internal/naisapi/protoapi"
)

const (
	// listTimeout bounds the call to Nais API.
	listTimeout = time.Minute
	// resolveTimeout bounds one registry lookup, so that a hanging registry cannot stall the sync.
	resolveTimeout = 30 * time.Second
	// resolveTTL is how long a tag's digest is reused before the registry is asked again, so
	// that a moved tag is noticed.
	resolveTTL = time.Hour
	// resolveConcurrency bounds concurrent registry requests.
	resolveConcurrency = 8
)

// Resolver returns the digest a tagged image reference points to.
type Resolver interface {
	Digest(ctx context.Context, ref name.Tag) (string, error)
}

// Inventory reads workload images from Nais API. It caches resolved tags; it is safe for
// concurrent use.
type Inventory struct {
	client   protoapi.WorkloadsClient
	resolver Resolver
	log      *slog.Logger
	now      func() time.Time

	mu   sync.Mutex
	tags map[string]resolved // by normalized tag reference
}

type resolved struct {
	digest string
	at     time.Time
}

// New returns an Inventory that lists workloads through client.
func New(client protoapi.WorkloadsClient, resolver Resolver, log *slog.Logger) *Inventory {
	return &Inventory{
		client:   client,
		resolver: resolver,
		log:      log,
		now:      time.Now,
		tags:     map[string]resolved{},
	}
}

// Snapshot returns the complete set of workload images in each environment Nais API has
// synced. A workload whose image tag cannot be resolved, and has never been, is left out.
func (inv *Inventory) Snapshot(ctx context.Context) (map[string][]v0s.WorkloadImage, error) {
	listCtx, cancel := context.WithTimeout(ctx, listTimeout)
	resp, err := inv.client.ListImages(listCtx, &protoapi.ListWorkloadImagesRequest{})
	cancel()
	if err != nil {
		return nil, fmt.Errorf("listing workload images in Nais API: %w", err)
	}
	envs := resp.GetEnvironments()

	var tags []name.Tag
	seen := map[string]bool{}
	for _, env := range envs {
		for _, w := range env.GetWorkloads() {
			ref, err := parseImage(w.GetImage())
			if err != nil {
				continue // reported below
			}
			if tag, ok := ref.(name.Tag); ok && !seen[tag.Name()] {
				seen[tag.Name()] = true
				tags = append(tags, tag)
			}
		}
	}
	digests := inv.resolve(ctx, tags)

	out := make(map[string][]v0s.WorkloadImage, len(envs))
	for _, env := range envs {
		if env.GetEnvironment() == "" {
			return nil, errors.New("listing workload images in Nais API: environment without a name")
		}
		if _, dup := out[env.GetEnvironment()]; dup {
			return nil, fmt.Errorf("listing workload images in Nais API: environment %q twice", env.GetEnvironment())
		}
		images := []v0s.WorkloadImage{}
		for _, w := range env.GetWorkloads() {
			wlog := inv.log.With("environment", env.GetEnvironment(), "namespace", w.GetTeamSlug(), "workload", w.GetName())
			kind, ok := ownerKinds[w.GetKind()]
			if !ok {
				wlog.With("kind", w.GetKind()).Warn("skipping workload of unknown kind")
				continue
			}
			ref, err := parseImage(w.GetImage())
			if err != nil {
				wlog.With("err", err).Warn("skipping workload with unparsable image")
				continue
			}
			digest := ref.Identifier()
			if tag, ok := ref.(name.Tag); ok {
				if digest, ok = digests[tag.Name()]; !ok {
					continue // resolve logged it
				}
			}
			images = append(images, v0s.WorkloadImage{
				Cluster:   env.GetEnvironment(),
				Namespace: w.GetTeamSlug(),
				Workload:  w.GetName(),
				// Naiserator names a workload's container after the workload.
				Container: w.GetName(),
				OwnerKind: kind,
				ImageName: repository(ref.Context()),
				Digest:    digest,
			})
		}
		out[env.GetEnvironment()] = images
	}
	return out, nil
}

var ownerKinds = map[protoapi.WorkloadKind]string{
	protoapi.WorkloadKind_APPLICATION: "Application",
	protoapi.WorkloadKind_JOB:         "Job",
}

// parseImage returns the image's digest reference if it has one, else its tag reference.
func parseImage(image string) (name.Reference, error) {
	if image == "" {
		return nil, errors.New("no image")
	}
	return name.ParseReference(image)
}

// repository names a repository as container runtimes report it: Docker Hub as docker.io.
func repository(r name.Repository) string {
	if r.RegistryStr() == name.DefaultRegistry {
		return "docker.io/" + r.RepositoryStr()
	}
	return r.Name()
}

// resolve returns the digest of every tag it can. A tag resolved within resolveTTL is not
// looked up again; a failed lookup falls back to the last known digest. Tags not in tags are
// forgotten.
func (inv *Inventory) resolve(ctx context.Context, tags []name.Tag) map[string]string {
	now := inv.now()
	inv.mu.Lock()
	cached := inv.tags
	inv.mu.Unlock()

	var (
		mu      sync.Mutex
		next    = make(map[string]resolved, len(tags))
		digests = make(map[string]string, len(tags))
		wg      sync.WaitGroup
		sem     = make(chan struct{}, resolveConcurrency)
	)
	for _, tag := range tags {
		key := tag.Name() // normalized: redis:7 and docker.io/library/redis:7 are one tag
		if c, ok := cached[key]; ok && now.Sub(c.at) < resolveTTL {
			next[key], digests[key] = c, c.digest
			continue
		}
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			resolveCtx, cancel := context.WithTimeout(ctx, resolveTimeout)
			digest, err := inv.resolver.Digest(resolveCtx, tag)
			cancel()
			mu.Lock()
			defer mu.Unlock()
			switch c, ok := cached[key]; {
			case err == nil:
				next[key], digests[key] = resolved{digest: digest, at: now}, digest
			case ok:
				inv.log.With("image", key, "err", err).Warn("resolving image tag; using last known digest")
				next[key], digests[key] = c, c.digest
			default:
				inv.log.With("image", key, "err", err).Warn("resolving image tag; skipping its workloads")
			}
		})
	}
	wg.Wait()

	inv.mu.Lock()
	inv.tags = next
	inv.mu.Unlock()
	return digests
}

// RegistryResolver resolves tags with a HEAD request to the registry.
type RegistryResolver struct {
	Keychain authn.Keychain
}

// Digest returns the digest of the manifest or index ref points to.
func (r RegistryResolver) Digest(ctx context.Context, ref name.Tag) (string, error) {
	desc, err := remote.Head(ref, remote.WithContext(ctx), remote.WithAuthFromKeychain(r.Keychain))
	if err != nil {
		return "", err
	}
	return desc.Digest.String(), nil
}
