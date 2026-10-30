// Package naisapi lists the images of Nais workloads (applications and jobs) from Nais API.
package naisapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/nais/v0s"
)

const (
	// maxResponse bounds the GraphQL response. All of nav's ~5000 workloads take 1.5 MB.
	maxResponse = 64 << 20
	// maxWorkloads is the page size per environment. A larger environment is an error rather
	// than a silently truncated snapshot.
	maxWorkloads = 100_000
	// resolveTTL is how long a tag's digest is reused before the registry is asked again, so
	// that a moved tag is noticed.
	resolveTTL = time.Hour
	// resolveConcurrency bounds concurrent registry requests.
	resolveConcurrency = 8
)

const query = `query ($first: Int!) {
	environments {
		nodes {
			name
			workloads(first: $first) {
				pageInfo { hasNextPage }
				nodes {
					__typename
					name
					team { slug }
					image { name tag digest }
				}
			}
		}
	}
}`

// Resolver returns the digest a tagged image reference points to.
type Resolver interface {
	Digest(ctx context.Context, ref name.Tag) (string, error)
}

// Inventory reads workload images from Nais API. It caches resolved tags; it is safe for
// concurrent use.
type Inventory struct {
	url      string
	token    string
	http     *http.Client
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

// New returns an Inventory that queries the GraphQL endpoint at url with an API key.
func New(url, token string, client *http.Client, resolver Resolver, log *slog.Logger) *Inventory {
	return &Inventory{
		url:      url,
		token:    token,
		http:     client,
		resolver: resolver,
		log:      log,
		now:      time.Now,
		tags:     map[string]resolved{},
	}
}

// Snapshot returns the complete set of workload images in each environment Nais API knows.
// Nais API only serves once its caches are synced, so an environment's set is complete. A
// workload whose image tag cannot be resolved, and has never been, is left out.
func (inv *Inventory) Snapshot(ctx context.Context) (map[string][]v0s.WorkloadImage, error) {
	envs, err := inv.query(ctx)
	if err != nil {
		return nil, err
	}

	var tags []name.Tag
	seen := map[string]bool{}
	for _, env := range envs {
		for _, w := range env.Workloads.Nodes {
			ref, err := parseImage(w.Image)
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
		if env.Workloads.PageInfo.HasNextPage {
			return nil, fmt.Errorf("environment %q has more than %d workloads", env.Name, maxWorkloads)
		}
		images := []v0s.WorkloadImage{}
		for _, w := range env.Workloads.Nodes {
			wlog := inv.log.With("environment", env.Name, "namespace", w.Team.Slug, "workload", w.Name)
			ref, err := parseImage(w.Image)
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
				Cluster:   env.Name,
				Namespace: w.Team.Slug,
				Workload:  w.Name,
				// Naiserator names a workload's container after the workload.
				Container: w.Name,
				OwnerKind: w.Typename,
				ImageName: repository(ref.Context()),
				Digest:    digest,
			})
		}
		out[env.Name] = images
	}
	return out, nil
}

type environment struct {
	Name      string `json:"name"`
	Workloads struct {
		PageInfo struct {
			HasNextPage bool `json:"hasNextPage"`
		} `json:"pageInfo"`
		Nodes []workload `json:"nodes"`
	} `json:"workloads"`
}

type workload struct {
	Typename string `json:"__typename"`
	Name     string `json:"name"`
	Team     struct {
		Slug string `json:"slug"`
	} `json:"team"`
	Image image `json:"image"`
}

type image struct {
	Name   string  `json:"name"`
	Tag    string  `json:"tag"`
	Digest *string `json:"digest"`
}

func (inv *Inventory) query(ctx context.Context) ([]environment, error) {
	body, err := json.Marshal(map[string]any{"query": query, "variables": map[string]int{"first": maxWorkloads}})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, inv.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+inv.token)
	resp, err := inv.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("querying Nais API: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("querying Nais API: status %s", resp.Status)
	}

	var result struct {
		Data struct {
			Environments struct {
				Nodes []environment `json:"nodes"`
			} `json:"environments"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return nil, fmt.Errorf("reading Nais API response: %w", err)
	}
	if len(data) > maxResponse {
		return nil, fmt.Errorf("reading Nais API response: exceeds %d bytes", maxResponse)
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("decoding Nais API response: %w", err)
	}
	// Partial data with errors is not a complete snapshot.
	if len(result.Errors) > 0 {
		return nil, fmt.Errorf("querying Nais API: %s", result.Errors[0].Message)
	}
	return result.Data.Environments.Nodes, nil
}

// parseImage returns the image's digest reference if it has one, else its tag reference.
func parseImage(img image) (name.Reference, error) {
	if img.Name == "" {
		return nil, errors.New("no image name")
	}
	if img.Digest != nil && *img.Digest != "" {
		return name.NewDigest(img.Name + "@" + *img.Digest)
	}
	ref := img.Name
	if img.Tag != "" {
		ref += ":" + img.Tag
	}
	return name.NewTag(ref)
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
			digest, err := inv.resolver.Digest(ctx, tag)
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
