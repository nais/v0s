// Package attest fetches CycloneDX SBOMs attested to images with cosign, and verifies that a
// GitHub Actions workflow in a trusted organization signed them.
package attest

import (
	"context"
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
	"github.com/google/go-containerregistry/pkg/v1/google"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/oci"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/sigstore-go/pkg/root"
)

// ErrNotFound is returned when an image has no verified CycloneDX attestation.
var ErrNotFound = errors.New("attestation not found")

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
}

// NewFetcher verifies attestations signed by GitHub Actions workflows in the given GitHub organizations.
// ctx must live for the service lifetime, since cached credentials reuse it for token refresh.
func NewFetcher(ctx context.Context, organizations []string, log *slog.Logger) (*Fetcher, error) {
	if len(organizations) == 0 {
		return nil, errors.New("no GitHub organizations to trust")
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
	sigs, err := f.verify(ctx, digest)
	if isNotFound(err) {
		return nil, fmt.Errorf("%w: %v", ErrNotFound, err)
	}
	if err != nil {
		return nil, fmt.Errorf("verifying attestations: %w", err)
	}
	envelopes := make([][]byte, 0, len(sigs))
	for _, sig := range sigs {
		envelope, err := sig.Payload()
		if err != nil {
			return nil, fmt.Errorf("reading attestation payload: %w", err)
		}
		envelopes = append(envelopes, envelope)
	}
	return selectCycloneDX(envelopes)
}

func (f *Fetcher) verify(ctx context.Context, ref name.Reference) ([]oci.Signature, error) {
	co := f.checkOpts(ctx)
	sigs, _, err := cosign.VerifyImageAttestations(ctx, ref, co)
	if _, ok := errors.AsType[*cosign.ErrNoMatchingAttestations](err); !ok {
		return sigs, err
	}
	// Images attested with cosign before v3 only have attestations in the legacy .att tag format.
	f.log.With("ref", ref.String()).Debug("no attestations in bundle format, trying legacy format")
	co.NewBundleFormat = false
	sigs, _, err = cosign.VerifyImageAttestations(ctx, ref, co)
	return sigs, err
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
	if _, ok := errors.AsType[*cosign.ErrNoMatchingAttestations](err); ok {
		return true
	}
	if terr, ok := errors.AsType[*transport.Error](err); ok && terr.StatusCode == http.StatusNotFound {
		for _, d := range terr.Errors {
			if d.Code == transport.ManifestUnknownErrorCode {
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
