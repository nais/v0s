// Package attest fetches and verifies CycloneDX SBOM attestations with cosign.
package attest

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/authn/github"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/google"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/oci"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/cosign/v3/pkg/oci/static"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// ErrNotFound is returned when an image has no verified CycloneDX attestation.
var ErrNotFound = errors.New("attestation not found")

var ErrRejected = errors.New("SBOM attestation was rejected")

const (
	// githubIssuer is the OIDC issuer of GitHub Actions workflow identities.
	githubIssuer = "https://token.actions.githubusercontent.com"
	// predicateCycloneDX is the in-toto predicate type of a CycloneDX SBOM.
	predicateCycloneDX = "https://cyclonedx.org/bom"
)

// Fetcher fetches and verifies SBOM attestations.
type Fetcher struct {
	log         *slog.Logger
	keychain    authn.Keychain
	trustedRoot root.TrustedMaterial
	identity    cosign.Identity
	rules       []IdentityRule
}

// NewFetcher verifies GitHub workflow identities and optional scoped identity rules.
// ctx must live for the service lifetime, since cached credentials reuse it for token refresh.
func NewFetcher(ctx context.Context, organizations []string, rules []IdentityRule, log *slog.Logger) (*Fetcher, error) {
	if len(organizations) == 0 {
		return nil, errors.New("no GitHub organizations to trust")
	}
	if err := validateIdentityRules(rules); err != nil {
		return nil, err
	}
	trustedRoot, err := cosign.TrustedRoot()
	if err != nil {
		return nil, fmt.Errorf("getting sigstore trusted root: %w", err)
	}
	return &Fetcher{
		log: log,
		keychain: lifetimeKeychain{
			ctx:      ctx,
			keychain: authn.NewMultiKeychain(authn.DefaultKeychain, google.Keychain, github.Keychain),
		},
		trustedRoot: trustedRoot,
		identity:    githubIdentity(organizations),
		rules:       rules,
	}, nil
}

// lifetimeKeychain keeps cached token sources on the service context rather than
// a fetch's short-lived context. Google credentials can retain the context from
// their first resolution and reuse it when refreshing tokens hours later.
// Registry requests still use the per-fetch context in checkOpts.
// Credential resolution itself follows the service's cancellation, not the fetch deadline.
type lifetimeKeychain struct {
	ctx      context.Context
	keychain authn.Keychain
}

func (k lifetimeKeychain) Resolve(resource authn.Resource) (authn.Authenticator, error) {
	return authn.Resolve(k.ctx, k.keychain, resource)
}

// githubIdentity accepts certificates issued to any workflow under .github/workflows in a
// repository owned by one of organizations.
//
// TODO: the SAN of a GitHub Actions certificate names the workflow that signed, which for a
// reusable workflow is the called workflow, not the caller. A repository outside the allowed
// organizations that calls a public reusable workflow in them therefore matches. This is only
// exploitable if such a workflow signs attestations from caller-supplied input. Consider also
// requiring the source repository owner certificate extension to be an allowed organization.
func githubIdentity(organizations []string) cosign.Identity {
	orgs := make([]string, len(organizations))
	for i, org := range organizations {
		orgs[i] = regexp.QuoteMeta(org)
	}
	subject := `^https://github\.com/(` + strings.Join(orgs, "|") + `)/[a-zA-Z0-9_.-]+?/\.github/workflows/.+?(?:\.yaml|\.yml).*$`
	return cosign.Identity{Issuer: githubIssuer, SubjectRegExp: subject}
}

// Fetch returns the verified CycloneDX JSON SBOM attested to ref ("repo@sha256:..."). It returns
// ErrNotFound if the image has no matching attestation.
func (f *Fetcher) Fetch(ctx context.Context, ref string) ([]byte, error) {
	digest, err := name.NewDigest(ref)
	if err != nil {
		return nil, fmt.Errorf("parsing image reference: %w", err)
	}
	candidates, discoveryErr := f.discover(ctx, digest)
	return f.verifyCandidates(ctx, digest, candidates, f.checkOpts(ctx), discoveryErr)
}

type candidate struct {
	bundle verify.SignedEntity
	legacy oci.Signature
}

func (f *Fetcher) discover(ctx context.Context, ref name.Digest) ([]candidate, error) {
	co := f.checkOpts(ctx)
	var candidates []candidate
	var errs []error
	index, err := ociremote.Referrers(ref, "", co.RegistryClientOpts...)
	if err != nil {
		errs = append(errs, fmt.Errorf("listing bundle referrers: %w", err))
	} else {
		for _, desc := range index.Manifests {
			bundleRef := ref.Context().Digest(desc.Digest.String())
			if !strings.HasPrefix(desc.ArtifactType, "application/vnd.dev.sigstore.bundle") {
				img, err := remote.Image(bundleRef, remote.WithAuthFromKeychain(f.keychain), remote.WithContext(ctx))
				if err != nil {
					errs = append(errs, fmt.Errorf("reading referrer: %w", err))
					continue
				}
				manifest, err := img.Manifest()
				if err != nil {
					errs = append(errs, fmt.Errorf("reading referrer manifest: %w", err))
					continue
				}
				isBundle := false
				for _, layer := range manifest.Layers {
					isBundle = isBundle || strings.HasPrefix(string(layer.MediaType), "application/vnd.dev.sigstore.bundle")
				}
				if !isBundle {
					continue
				}
			}
			b, err := ociremote.Bundle(bundleRef, co.RegistryClientOpts...)
			if err != nil {
				errs = append(errs, fmt.Errorf("reading bundle candidate: %w", err))
				continue
			}
			candidates = append(candidates, candidate{bundle: b})
		}
	}
	tag, err := ociremote.AttestationTag(ref, co.RegistryClientOpts...)
	if err != nil {
		errs = append(errs, err)
	} else {
		desc, err := remote.Get(tag, remote.WithAuthFromKeychain(f.keychain), remote.WithContext(ctx))
		if err != nil {
			if !isNotFound(err) {
				errs = append(errs, fmt.Errorf("reading legacy attestation manifest: %w", err))
			}
		} else {
			atts, err := ociremote.Signatures(ref.Context().Digest(desc.Digest.String()), co.RegistryClientOpts...)
			if err != nil {
				errs = append(errs, err)
			} else {
				sigs, err := atts.Get()
				if err != nil {
					errs = append(errs, err)
				}
				for _, sig := range sigs {
					candidates = append(candidates, candidate{legacy: sig})
				}
			}
		}
	}
	return candidates, errors.Join(errs...)
}

func (f *Fetcher) verifyCandidates(ctx context.Context, ref name.Digest, candidates []candidate, opts *cosign.CheckOpts, discoveryErr error) ([]byte, error) {
	hash, err := v1.NewHash(ref.DigestStr())
	if err != nil {
		return nil, err
	}
	var rejected []error
	for _, candidate := range candidates {
		var attempts []error
		for _, identity := range f.identities(ref.Context()) {
			co := *opts
			co.Identities = []cosign.Identity{identity}
			payload, err := candidate.verify(ctx, hash, &co)
			if err != nil {
				attempts = append(attempts, err)
				continue
			}
			doc, err := selectCycloneDX([][]byte{payload})
			if err == nil {
				if discoveryErr != nil {
					f.log.With("ref", ref.String(), "err", discoveryErr).Warn("some attestation candidates could not be read")
				}
				return doc, nil
			}
			if !errors.Is(err, ErrNotFound) {
				attempts = append(attempts, err)
				continue
			}
			attempts = nil
			break
		}
		rejected = append(rejected, attempts...)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if discoveryErr != nil {
		return nil, discoveryErr
	}
	if len(rejected) > 0 {
		f.log.With("ref", ref.String(), "err", errors.Join(rejected...)).Warn("attestations rejected")
		return nil, ErrRejected
	}
	return nil, ErrNotFound
}

func (c candidate) verify(ctx context.Context, hash v1.Hash, co *cosign.CheckOpts) ([]byte, error) {
	if c.legacy != nil {
		co.NewBundleFormat = false
		if _, err := cosign.VerifyBlobAttestation(ctx, c.legacy, hash, co); err != nil {
			return nil, err
		}
		return c.legacy.Payload()
	}
	digest, err := hex.DecodeString(hash.Hex)
	if err != nil {
		return nil, err
	}
	if _, err := cosign.VerifyNewBundle(ctx, co, verify.WithArtifactDigest(hash.Algorithm, digest), c.bundle); err != nil {
		return nil, err
	}
	content, err := c.bundle.SignatureContent()
	if err != nil {
		return nil, err
	}
	if content.EnvelopeContent() == nil {
		return nil, errors.New("bundle does not contain a DSSE envelope")
	}
	payload, err := json.Marshal(content.EnvelopeContent().RawEnvelope())
	if err != nil {
		return nil, err
	}
	att, err := static.NewAttestation(payload)
	if err != nil {
		return nil, err
	}
	if err := co.ClaimVerifier(att, hash, co.Annotations); err != nil {
		return nil, err
	}
	return payload, nil
}

// checkOpts returns the options for verifying attestations, starting with the bundle format.
// ClaimVerifier binds a legacy-format attestation to the image: without it cosign checks only the
// signature, and would accept a signed attestation copied from another image's .att tag.
func (f *Fetcher) checkOpts(ctx context.Context) *cosign.CheckOpts {
	return &cosign.CheckOpts{
		RegistryClientOpts: []ociremote.Option{
			ociremote.WithRemoteOptions(remote.WithAuthFromKeychain(f.keychain), remote.WithContext(ctx)),
		},
		TrustedMaterial: f.trustedRoot,
		Identities:      []cosign.Identity{f.identity},
		ClaimVerifier:   cosign.IntotoSubjectClaimVerifier,
		NewBundleFormat: true,
	}
}

// isNotFound reports whether err means that the image has no matching attestation.
func isNotFound(err error) bool {
	if terr, ok := errors.AsType[*transport.Error](err); ok && terr.StatusCode == http.StatusNotFound {
		for _, d := range terr.Errors {
			if d.Code == transport.ManifestUnknownErrorCode || d.Code == transport.NameUnknownErrorCode {
				return true
			}
		}
	}
	return false
}

// selectCycloneDX returns the predicate of the first CycloneDX in-toto statement among DSSE
// envelopes, exactly as attested. Envelopes that do not parse are skipped.
func selectCycloneDX(envelopes [][]byte) ([]byte, error) {
	for _, envelope := range envelopes {
		var env struct {
			Payload []byte `json:"payload"`
		}
		if err := json.Unmarshal(envelope, &env); err != nil {
			continue
		}
		var statement struct {
			PredicateType string          `json:"predicateType"`
			Predicate     json.RawMessage `json:"predicate"`
		}
		if err := json.Unmarshal(env.Payload, &statement); err != nil {
			continue
		}
		if statement.PredicateType == predicateCycloneDX && len(statement.Predicate) > 0 {
			return statement.Predicate, nil
		}
	}
	return nil, fmt.Errorf("%w: no CycloneDX statement among %d verified attestations", ErrNotFound, len(envelopes))
}
