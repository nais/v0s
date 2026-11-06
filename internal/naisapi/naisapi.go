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

	"github.com/nais/v0s/internal/naisapi/protoapi"
	"github.com/nais/v0s/internal/v0s"
)

const (
	// listTimeout bounds the call to Nais API.
	listTimeout = time.Minute
	// resolveTimeout bounds one registry lookup, so that a hanging registry cannot stall the sync.
	resolveTimeout = 30 * time.Second
	// resolveConcurrency bounds concurrent registry requests.
	resolveConcurrency = 8
)

// Resolver returns the digest a tagged image reference points to.
type Resolver interface {
	Digest(ctx context.Context, ref name.Tag) (string, error)
}

// Inventory reads workload images from Nais API. It resolves each tag once, and is not safe
// for concurrent use.
type Inventory struct {
	client   protoapi.WorkloadsClient
	resolver Resolver
	log      *slog.Logger
	digests  map[string]string // by normalized tag reference
}

// New returns an Inventory that lists workloads through client.
func New(client protoapi.WorkloadsClient, resolver Resolver, log *slog.Logger) *Inventory {
	return &Inventory{client: client, resolver: resolver, log: log, digests: map[string]string{}}
}

// Snapshot returns the complete set of workload images in each environment Nais API has
// synced. A workload whose image cannot be resolved to a digest is included with the reason.
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
	digests, errs := inv.resolve(ctx, tags)

	out := make(map[string][]v0s.WorkloadImage, len(envs))
	for _, env := range envs {
		images := []v0s.WorkloadImage{}
		for _, w := range env.GetWorkloads() {
			wi := v0s.WorkloadImage{
				Environment: env.GetEnvironment(),
				Team:        w.GetTeamSlug(),
				Workload:    w.GetName(),
				Reference:   w.GetImage(),
			}
			ref, err := parseImage(w.GetImage())
			switch {
			case err != nil:
				wi.ResolveError = err.Error()
			case errs[ref.Name()] != nil:
				wi.ResolveError = errs[ref.Name()].Error()
			default:
				wi.ImageName = repository(ref.Context())
				wi.Digest = ref.Identifier()
				if _, ok := ref.(name.Tag); ok {
					wi.Digest = digests[ref.Name()]
				}
			}
			images = append(images, wi)
		}
		out[env.GetEnvironment()] = images
	}
	return out, nil
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

// resolve returns the digest of every tag it can, and the error of every tag it cannot. A tag
// is looked up in the registry once and its digest kept while the tag is in use, so a tag moved
// in the registry is not noticed. A failed lookup is retried on the next call.
func (inv *Inventory) resolve(ctx context.Context, tags []name.Tag) (map[string]string, map[string]error) {
	var (
		mu      sync.Mutex
		digests = make(map[string]string, len(tags))
		errs    = map[string]error{}
		wg      sync.WaitGroup
		sem     = make(chan struct{}, resolveConcurrency)
	)
	for _, tag := range tags {
		key := tag.Name() // normalized: redis:7 and docker.io/library/redis:7 are one tag
		if digest, ok := inv.digests[key]; ok {
			digests[key] = digest
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
			if err != nil {
				inv.log.With("image", key, "err", err).Warn("resolving image tag")
				errs[key] = fmt.Errorf("resolving %s: %w", key, err)
				return
			}
			digests[key] = digest
		})
	}
	wg.Wait()
	inv.digests = digests
	return digests, errs
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
