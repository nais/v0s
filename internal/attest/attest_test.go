package attest

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	registryempty "github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/google"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	registrystatic "github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	cbundle "github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v3/pkg/oci"
	"github.com/sigstore/cosign/v3/pkg/oci/empty"
	"github.com/sigstore/cosign/v3/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/cosign/v3/pkg/oci/static"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/tlog"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

// TestFetchRegistryDeadline exercises the real cosign/registry path against a
// server that never sends response headers. A transport's dial/TLS timeouts do
// not bound this wait; the caller's context must reach the registry request.
func TestFetchRegistryDeadline(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		select {
		case started <- struct{}{}:
		default:
		}
		<-r.Context().Done()
	}))
	defer srv.Close()
	f := &Fetcher{
		log: slog.New(slog.DiscardHandler), keychain: authn.NewMultiKeychain(),
		trustedRoot: vs, identity: githubIdentity([]string{"nais"}),
	}
	ctx, cancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
	defer cancel()
	ref := strings.TrimPrefix(srv.URL, "http://") + "/app@sha256:" + strings.Repeat("a", 64)
	_, err = f.Fetch(ctx, ref)
	if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrNotFound) {
		t.Errorf("Fetch error = %v; want deadline exceeded, not missing attestation", err)
	}
	select {
	case <-started:
	default:
		t.Error("no registry request reached the stalled endpoint")
	}
}

type contextKeychainFunc func(context.Context, authn.Resource) (authn.Authenticator, error)

func (f contextKeychainFunc) Resolve(r authn.Resource) (authn.Authenticator, error) {
	return f(context.Background(), r)
}

func (f contextKeychainFunc) ResolveContext(ctx context.Context, r authn.Resource) (authn.Authenticator, error) {
	return f(ctx, r)
}

func TestCredentialRefreshAfterFetchCancellation(t *testing.T) {
	// Use only a synthetic helper, never the developer's credentials. An expired
	// token forces refresh on every Authorization call without waiting an hour.
	dir := t.TempDir()
	script := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' '{\"credential\":{\"access_token\":\"synthetic-token\",\"token_expiry\":\"%s\"}}'\n",
		time.Now().Add(-time.Hour).UTC().Format(time.RFC3339))
	if err := os.WriteFile(filepath.Join(dir, "gcloud"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	serviceCtx, stop := context.WithCancel(t.Context())
	defer stop()
	keychain := lifetimeKeychain{serviceCtx, contextKeychainFunc(func(ctx context.Context, _ authn.Resource) (authn.Authenticator, error) {
		return google.NewGcloudAuthenticator(ctx)
	})}
	registry, err := name.NewRegistry("europe-north1-docker.pkg.dev")
	if err != nil {
		t.Fatal(err)
	}
	fetchCtx, cancel := context.WithCancel(serviceCtx)
	defer cancel()
	auth, err := authn.Resolve(fetchCtx, keychain, registry)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err := auth.Authorization(); err != nil {
		t.Fatalf("cached credentials failed to refresh after a fetch ended: %v", err)
	}
	stop()
	if _, err := auth.Authorization(); !errors.Is(err, context.Canceled) {
		t.Errorf("refresh after service shutdown: %v; want context canceled", err)
	}
}

func TestGitHubIdentity(t *testing.T) {
	identity := githubIdentity([]string{"nais", "navikt", "a.b"})
	if identity.Issuer != "https://token.actions.githubusercontent.com" {
		t.Errorf("Issuer = %q", identity.Issuer)
	}
	subject := regexp.MustCompile(identity.SubjectRegExp)

	tests := []struct {
		subject string
		want    bool
	}{
		{"https://github.com/nais/app/.github/workflows/build.yml@refs/heads/main", true},
		{"https://github.com/navikt/app/.github/workflows/deploy.yaml@refs/pull/1/merge", true},
		{"https://github.com/nais/app/.github/workflows/PROD%20deploy.yml@refs/tags/v1", true},
		{"https://github.com/a.b/app/.github/workflows/build.yml@refs/heads/main", true},
		{"https://github.com/aXb/app/.github/workflows/build.yml@refs/heads/main", false},
		{"https://github.com/evil/app/.github/workflows/build.yml@refs/heads/main", false},
		{"https://github.com/naisx/app/.github/workflows/build.yml@refs/heads/main", false},
		{"https://github.com/nais/app/build.yml@refs/heads/main", false},
		{"https://github.com/nais/app/other/.github/workflows/build.yml@refs/heads/main", false},
		{"https://github.com/nais/app/.github/actions/build.yml@refs/heads/main", false},
		{"https://evil.com/nais/app/.github/workflows/build.yml@refs/heads/main", false},
	}
	for _, tt := range tests {
		t.Run(tt.subject, func(t *testing.T) {
			if got := subject.MatchString(tt.subject); got != tt.want {
				t.Errorf("subject regexp matches %q = %v, want %v", tt.subject, got, tt.want)
			}
		})
	}
}

func TestSelectCycloneDX(t *testing.T) {
	cyclonedx := envelope(t, "testdata/cyclonedx-statement.json")
	slsa := envelope(t, "testdata/slsa-statement.json")
	predicate, err := os.ReadFile("testdata/cyclonedx-predicate.json")
	if err != nil {
		t.Fatal(err)
	}
	predicate = bytes.TrimSpace(predicate)

	tests := []struct {
		name      string
		envelopes [][]byte
		want      []byte
		wantErr   error
	}{
		{name: "only CycloneDX", envelopes: [][]byte{cyclonedx}, want: predicate},
		{name: "CycloneDX after other predicate", envelopes: [][]byte{slsa, cyclonedx}, want: predicate},
		{name: "malformed envelope skipped", envelopes: [][]byte{[]byte("not json"), cyclonedx}, want: predicate},
		{name: "no CycloneDX", envelopes: [][]byte{slsa}, wantErr: ErrNotFound},
		{name: "none", wantErr: ErrNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := selectCycloneDX(tt.envelopes)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("selectCycloneDX() error = %v, want %v", err, tt.wantErr)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("selectCycloneDX() =\n%s\nwant\n%s", got, tt.want)
			}
		})
	}
}

// envelope wraps the in-toto statement in file in a DSSE envelope, as cosign returns it.
func envelope(t *testing.T, file string) []byte {
	t.Helper()
	statement, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	env, err := json.Marshal(struct {
		PayloadType string `json:"payloadType"`
		Payload     []byte `json:"payload"`
	}{"application/vnd.in-toto+json", statement})
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// TestCheckOptsBindLegacyAttestationToImage verifies a validly signed legacy-format attestation
// for image A against image A and image B. The signature is real, from a virtual Sigstore
// instance; only the SCT check is skipped, because its certificates have no embedded SCTs.
func TestCheckOptsBindLegacyAttestationToImage(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	statement, err := os.ReadFile("testdata/cyclonedx-statement.json")
	if err != nil {
		t.Fatal(err)
	}
	entity, err := vs.Attest("https://github.com/nais/app/.github/workflows/build.yml@refs/heads/main", githubIssuer, statement)
	if err != nil {
		t.Fatal(err)
	}
	atts := legacyAttestations(t, vs, entity)

	f := &Fetcher{keychain: authn.DefaultKeychain, trustedRoot: vs, identity: githubIdentity([]string{"nais"})}
	co := f.checkOpts(t.Context())
	co.NewBundleFormat = false
	co.IgnoreSCT = true

	tests := []struct {
		name    string
		digest  string
		wantErr bool
	}{
		{name: "statement subject", digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{name: "other image", digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := v1.NewHash(tt.digest)
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = cosign.VerifyImageAttestation(t.Context(), atts, h, co)
			if tt.wantErr && err == nil {
				t.Fatal("VerifyImageAttestation() succeeded, want error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("VerifyImageAttestation(): %v", err)
			}
		})
	}
}

func TestScopedIdentityVerification(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	statement, err := os.ReadFile("testdata/cyclonedx-statement.json")
	if err != nil {
		t.Fatal(err)
	}
	rules, err := ParseIdentityRules(`[{"issuer":"https://accounts.google.com","subjectRegExp":"[a-zA-Z0-9._%+-]+@nav\\.no","repositories":["ghcr.io/navikt"]}]`)
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"bundle", "legacy"} {
		t.Run(format, func(t *testing.T) {
			for _, tc := range []struct {
				name, subject, issuer, repo, digest string
				noRules                             bool
				want                                error
			}{
				{name: "NAV", subject: "person@nav.no", issuer: "https://accounts.google.com"},
				{name: "wrong issuer", subject: "person@nav.no", issuer: githubIssuer, want: ErrRejected},
				{name: "wrong domain", subject: "person@example.com", issuer: "https://accounts.google.com", want: ErrRejected},
				{name: "domain suffix", subject: "person@nav.no.evil", issuer: "https://accounts.google.com", want: ErrRejected},
				{name: "wrong scope", subject: "person@nav.no", issuer: "https://accounts.google.com", repo: "ghcr.io/naviktx/app", want: ErrRejected},
				{name: "other instance", subject: "person@nav.no", issuer: "https://accounts.google.com", noRules: true, want: ErrRejected},
				{name: "wrong digest", subject: "person@nav.no", issuer: "https://accounts.google.com", digest: strings.Repeat("b", 64), want: ErrRejected},
				{name: "CI unchanged", subject: "https://github.com/nais/app/.github/workflows/build.yml@refs/heads/main", issuer: githubIssuer, noRules: true},
				{name: "CI outside scope", subject: "https://github.com/nais/app/.github/workflows/build.yml@refs/heads/main", issuer: githubIssuer, repo: "ghcr.io/other/app"},
				{name: "no issuer subject cross product", subject: "https://github.com/nais/app/.github/workflows/build.yml@refs/heads/main", issuer: "https://accounts.google.com", want: ErrRejected},
			} {
				t.Run(tc.name, func(t *testing.T) {
					entity, err := vs.Attest(tc.subject, tc.issuer, statement)
					if err != nil {
						t.Fatal(err)
					}
					c := candidate{bundle: entity}
					if format == "legacy" {
						sigs, err := legacyAttestations(t, vs, entity).Get()
						if err != nil {
							t.Fatal(err)
						}
						c = candidate{legacy: sigs[0]}
					}
					f := &Fetcher{log: slog.New(slog.DiscardHandler), trustedRoot: vs, identity: githubIdentity([]string{"nais"}), rules: rules}
					if tc.noRules {
						f.rules = nil
					}
					repo, digest := tc.repo, tc.digest
					if repo == "" {
						repo = "ghcr.io/navikt/app"
					}
					if digest == "" {
						digest = strings.Repeat("a", 64)
					}
					ref, err := name.NewDigest(repo + "@sha256:" + digest)
					if err != nil {
						t.Fatal(err)
					}
					co := f.checkOpts(t.Context())
					co.IgnoreSCT = true
					doc, err := f.verifyCandidates(t.Context(), ref, []candidate{c}, co, nil)
					if !errors.Is(err, tc.want) {
						t.Fatalf("error=%v, want %v", err, tc.want)
					}
					if tc.want == nil && !bytes.Contains(doc, []byte(`"bomFormat"`)) {
						t.Fatalf("not a CycloneDX predicate: %s", doc)
					}
				})
			}
		})
	}
}

func TestCandidateOutcomes(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	readCandidate := func(file, subject string) candidate {
		t.Helper()
		statement, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		entity, err := vs.Attest(subject, githubIssuer, statement)
		if err != nil {
			t.Fatal(err)
		}
		return candidate{bundle: entity}
	}
	ci := "https://github.com/nais/app/.github/workflows/build.yml@refs/heads/main"
	sbom := readCandidate("testdata/cyclonedx-statement.json", ci)
	rejected := readCandidate("testdata/cyclonedx-statement.json", "person@nav.no")
	slsa := readCandidate("testdata/slsa-statement.json", ci)
	statement, err := os.ReadFile("testdata/cyclonedx-statement.json")
	if err != nil {
		t.Fatal(err)
	}
	navEntity, err := vs.Attest("person@nav.no", "https://accounts.google.com", statement)
	if err != nil {
		t.Fatal(err)
	}
	rejectedSigs, err := legacyAttestations(t, vs, navEntity).Get()
	if err != nil {
		t.Fatal(err)
	}
	rejectedLegacy := candidate{legacy: rejectedSigs[0]}
	ref, err := name.NewDigest("ghcr.io/navikt/app@sha256:" + strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	f := &Fetcher{log: slog.New(slog.DiscardHandler), trustedRoot: vs, identity: githubIdentity([]string{"nais"})}
	co := f.checkOpts(t.Context())
	co.IgnoreSCT = true
	discoveryErr := errors.New("registry unavailable")
	for _, tc := range []struct {
		name       string
		candidates []candidate
		discovery  error
		want       error
	}{
		{"empty both formats", nil, nil, ErrNotFound},
		{"only other predicate", []candidate{slsa}, nil, ErrNotFound},
		{"rejected bundle empty legacy", []candidate{rejected}, nil, ErrRejected},
		{"rejected legacy empty bundle", []candidate{rejectedLegacy}, nil, ErrRejected},
		{"both rejected", []candidate{rejected, rejectedLegacy}, nil, ErrRejected},
		{"rejected with other predicate", []candidate{rejected, slsa}, nil, ErrRejected},
		{"valid among rejected", []candidate{rejected, sbom}, nil, nil},
		{"incomplete discovery", nil, discoveryErr, discoveryErr},
		{"valid despite incomplete discovery", []candidate{sbom}, discoveryErr, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := f.verifyCandidates(t.Context(), ref, tc.candidates, co, tc.discovery)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error=%v, want %v", err, tc.want)
			}
		})
	}
	rules, err := ParseIdentityRules(`[{"issuer":"https://accounts.google.com","subjectRegExp":"[a-zA-Z0-9._%+-]+@nav\\.no","repositories":["ghcr.io/navikt"]}]`)
	if err != nil {
		t.Fatal(err)
	}
	f.rules = rules
	if _, err := f.verifyCandidates(t.Context(), ref, []candidate{slsa, {bundle: navEntity}}, co, nil); err != nil {
		t.Fatalf("CI other predicate hid NAV SBOM: %v", err)
	}
}

func TestRejectedLegacyIsNotMissing(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	statement, err := os.ReadFile("testdata/cyclonedx-statement.json")
	if err != nil {
		t.Fatal(err)
	}
	entity, err := vs.Attest("person@nav.no", "https://accounts.google.com", statement)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(registry.New())
	defer srv.Close()
	ref, err := name.NewDigest(strings.TrimPrefix(srv.URL, "http://") + "/app@sha256:" + strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	tag, err := ociremote.AttestationTag(ref)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(tag, legacyAttestations(t, vs, entity), remote.WithAuth(authn.Anonymous), remote.WithContext(t.Context())); err != nil {
		t.Fatal(err)
	}
	f := &Fetcher{log: slog.New(slog.DiscardHandler), keychain: authn.NewMultiKeychain(), trustedRoot: vs, identity: githubIdentity([]string{"nais"})}
	_, err = f.Fetch(t.Context(), ref.String())
	if !errors.Is(err, ErrRejected) || errors.Is(err, ErrNotFound) {
		t.Fatalf("Fetch: %v; want rejected, not missing", err)
	}
}

func TestDiscoveryDoesNotHideUnreadableBundles(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, artifactType string
		wantErr            bool
	}{
		{name: "absent"},
		{name: "unrelated", artifactType: "application/example"},
		{name: "malformed bundle", artifactType: "application/vnd.dev.sigstore.bundle.v0.3+json", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(registry.New())
			defer srv.Close()
			ref, err := name.NewDigest(strings.TrimPrefix(srv.URL, "http://") + "/app@sha256:" + strings.Repeat("a", 64))
			if err != nil {
				t.Fatal(err)
			}
			if tc.artifactType != "" {
				image := registryempty.Image
				hash, err := image.Digest()
				if err != nil {
					t.Fatal(err)
				}
				ref = ref.Context().Digest(hash.String())
				if err := remote.Write(ref, image, remote.WithAuth(authn.Anonymous), remote.WithContext(t.Context())); err != nil {
					t.Fatal(err)
				}
				layer := registrystatic.NewLayer([]byte("not a bundle"), types.MediaType(tc.artifactType))
				if err := ociremote.WriteReferrer(ref, tc.artifactType, []v1.Layer{layer}, nil,
					ociremote.WithRemoteOptions(remote.WithAuth(authn.Anonymous), remote.WithContext(t.Context()))); err != nil {
					t.Fatal(err)
				}
			}
			f := &Fetcher{log: slog.New(slog.DiscardHandler), keychain: authn.NewMultiKeychain(), trustedRoot: vs, identity: githubIdentity([]string{"nais"})}
			candidates, err := f.discover(t.Context(), ref)
			if len(candidates) != 0 || (err != nil) != tc.wantErr {
				t.Fatalf("candidates=%d, err=%v, want error=%v", len(candidates), err, tc.wantErr)
			}
			_, fetchErr := f.Fetch(t.Context(), ref.String())
			if tc.wantErr {
				if fetchErr == nil || errors.Is(fetchErr, ErrNotFound) {
					t.Fatalf("unreadable bundle reported as absent: %v", fetchErr)
				}
			} else if !errors.Is(fetchErr, ErrNotFound) {
				t.Fatalf("Fetch: %v, want missing", fetchErr)
			}
		})
	}
}

func TestCandidateRetainsTrustAndSignatureChecks(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	other, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	statement, err := os.ReadFile("testdata/cyclonedx-statement.json")
	if err != nil {
		t.Fatal(err)
	}
	entity, err := vs.Attest("https://github.com/nais/app/.github/workflows/build.yml@refs/heads/main", githubIssuer, statement)
	if err != nil {
		t.Fatal(err)
	}
	sigs, err := legacyAttestations(t, vs, entity).Get()
	if err != nil {
		t.Fatal(err)
	}
	hash, err := v1.NewHash("sha256:" + strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	f := &Fetcher{trustedRoot: vs, identity: githubIdentity([]string{"nais"})}
	co := f.checkOpts(t.Context())
	co.IgnoreSCT = true
	payload, err := sigs[0].Payload()
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		PayloadType string          `json:"payloadType"`
		Payload     []byte          `json:"payload"`
		Signatures  json.RawMessage `json:"signatures"`
	}
	if err := json.Unmarshal(payload, &env); err != nil {
		t.Fatal(err)
	}
	env.Payload = bytes.ReplaceAll(env.Payload, []byte("CycloneDX"), []byte("CycloneDY"))
	tampered, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := sigs[0].Cert()
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := cryptoutils.MarshalCertificateToPEM(cert)
	if err != nil {
		t.Fatal(err)
	}
	rekor, err := sigs[0].Bundle()
	if err != nil {
		t.Fatal(err)
	}
	att, err := static.NewAttestation(tampered, static.WithCertChain(certPEM, nil), static.WithBundle(rekor))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (candidate{legacy: att}).verify(t.Context(), hash, co); err == nil {
		t.Fatal("tampered payload was accepted")
	}
	co.TrustedMaterial = other
	for _, c := range []candidate{{legacy: sigs[0]}, {bundle: entity}} {
		if _, err := c.verify(t.Context(), hash, co); err == nil {
			t.Fatal("untrusted certificate was accepted")
		}
	}
	co = f.checkOpts(t.Context())
	if co.IgnoreSCT || co.IgnoreTlog || co.ClaimVerifier == nil {
		t.Fatal("production verification requirements were weakened")
	}
}

// legacyAttestations stores entity as cosign stores attestations in the legacy .att tag: the DSSE
// envelope as payload, with certificate and Rekor bundle as annotations.
func legacyAttestations(t *testing.T, vs *ca.VirtualSigstore, entity *ca.TestEntity) oci.Signatures {
	t.Helper()
	sigContent, err := entity.SignatureContent()
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := json.Marshal(sigContent.EnvelopeContent().RawEnvelope())
	if err != nil {
		t.Fatal(err)
	}
	verification, err := entity.VerificationContent()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := cryptoutils.MarshalCertificateToPEM(verification.Certificate())
	if err != nil {
		t.Fatal(err)
	}
	entries, err := entity.TlogEntries()
	if err != nil {
		t.Fatal(err)
	}
	entry := entries[0]
	payload := tlog.RekorPayload{
		Body:           entry.Body(),
		IntegratedTime: entry.IntegratedTime().Unix(),
		LogIndex:       entry.LogIndex(),
		LogID:          hex.EncodeToString([]byte(entry.LogKeyID())),
	}
	// The entry does not expose its signed entry timestamp, so sign the same payload again.
	set, err := vs.RekorSignPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	rekorBundle := &cbundle.RekorBundle{
		SignedEntryTimestamp: set,
		Payload:              cbundle.RekorPayload(payload),
	}
	att, err := static.NewAttestation(envelope, static.WithCertChain(cert, nil), static.WithBundle(rekorBundle))
	if err != nil {
		t.Fatal(err)
	}
	atts, err := mutate.AppendSignatures(empty.Signatures(), false, att)
	if err != nil {
		t.Fatal(err)
	}
	return atts
}
