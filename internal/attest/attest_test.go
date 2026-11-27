package attest

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
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
	"github.com/google/go-containerregistry/pkg/v1/google"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	cbundle "github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v3/pkg/oci"
	"github.com/sigstore/cosign/v3/pkg/oci/empty"
	"github.com/sigstore/cosign/v3/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/cosign/v3/pkg/oci/static"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/tlog"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"google.golang.org/protobuf/encoding/protojson"
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
		trustedRoot: vs, identities: []cosign.Identity{githubIdentity([]string{"nais"})},
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

func TestEmailSignersIdentity(t *testing.T) {
	identity, err := EmailSigners{Issuer: " " + GoogleIssuer + " ", Domains: []string{"nav.no", " Example.COM"}}.identity()
	if err != nil {
		t.Fatal(err)
	}
	if identity.Issuer != GoogleIssuer {
		t.Errorf("Issuer = %q", identity.Issuer)
	}
	subject := regexp.MustCompile(identity.SubjectRegExp)
	for _, tt := range []struct {
		email string
		want  bool
	}{
		{"ola.nordmann@nav.no", true},
		{"kari@example.com", true},
		{"ola@navXno", false},
		{"ola@nav.no.evil.com", false},
		{"ola@evil.nav.no", false},
		{"ola@evilnav.no", false},
		{"ola@nav.no@evil.com", false},
	} {
		if got := subject.MatchString(tt.email); got != tt.want {
			t.Errorf("subject regexp matches %q = %v, want %v", tt.email, got, tt.want)
		}
	}

	for _, tt := range []struct {
		name, issuer, domain string
	}{
		{"plain HTTP issuer", "http://accounts.google.com", "nav.no"},
		{"GitHub issuer", githubIssuer, "nav.no"},
		{"single label", GoogleIssuer, "no"},
		{"wildcard domain", GoogleIssuer, "*.nav.no"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := (EmailSigners{Issuer: tt.issuer, Domains: []string{tt.domain}}).identity(); err == nil {
				t.Error("identity() succeeded, want error")
			}
		})
	}
}

// TestNewFetcherTrustsEmailSignersOnlyWithDomains checks that email signers are optional: without
// domains, an invalid issuer is ignored and only the GitHub identity is trusted.
func TestNewFetcherTrustsEmailSignersOnlyWithDomains(t *testing.T) {
	f, err := NewFetcher(t.Context(), []string{"nais"}, EmailSigners{Issuer: "not a URL"}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.identities) != 1 || f.identities[0].Issuer != githubIssuer {
		t.Errorf("identities = %v, want only GitHub", f.identities)
	}
	if _, err := NewFetcher(t.Context(), []string{"nais"}, EmailSigners{Issuer: "not a URL", Domains: []string{"nav.no"}}, slog.New(slog.DiscardHandler)); err == nil {
		t.Error("NewFetcher() accepted an invalid email issuer with domains")
	}
}

type signedStatement struct {
	subject, issuer, statement string
}

// TestFetchBundleIdentities verifies real bundle-format attestations from a virtual Sigstore
// instance, stored as OCI referrers in an in-memory registry, as cosign v3 attaches them. Cosign
// verifies bundles against one identity at a time, so this covers each configured identity alone
// and SBOM and provenance signed by different identities.
func TestFetchBundleIdentities(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	predicate, err := os.ReadFile("testdata/cyclonedx-predicate.json")
	if err != nil {
		t.Fatal(err)
	}
	predicate = bytes.TrimSpace(predicate)
	email, err := EmailSigners{Issuer: GoogleIssuer, Domains: []string{"nav.no"}}.identity()
	if err != nil {
		t.Fatal(err)
	}
	github := githubIdentity([]string{"nais"})
	const workflow = "https://github.com/nais/app/.github/workflows/build.yml@refs/heads/main"

	tests := []struct {
		name       string
		identities []cosign.Identity
		signed     []signedStatement
		wantErr    error
	}{
		{
			name:       "GitHub signer with email signers trusted",
			identities: []cosign.Identity{github, email},
			signed:     []signedStatement{{workflow, githubIssuer, "cyclonedx"}},
		},
		{
			name:       "email signer",
			identities: []cosign.Identity{github, email},
			signed:     []signedStatement{{"ola.nordmann@nav.no", GoogleIssuer, "cyclonedx"}},
		},
		{
			name:       "provenance and SBOM by different signers",
			identities: []cosign.Identity{github, email},
			signed:     []signedStatement{{workflow, githubIssuer, "slsa"}, {"ola.nordmann@nav.no", GoogleIssuer, "cyclonedx"}},
		},
		{
			name:       "email signer on untrusted domain",
			identities: []cosign.Identity{github, email},
			signed:     []signedStatement{{"ola@evil.com", GoogleIssuer, "cyclonedx"}},
			wantErr:    ErrNotFound,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			digest := pushImage(t)
			for _, s := range tt.signed {
				attachBundle(t, vs, digest, s)
			}
			f := &Fetcher{
				log: slog.New(slog.DiscardHandler), keychain: authn.DefaultKeychain,
				trustedRoot: vs, identities: tt.identities, ignoreSCT: true,
			}
			got, err := f.Fetch(t.Context(), digest.String())
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Fetch() error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Fetch(): %v", err)
			}
			if !bytes.Equal(got, predicate) {
				t.Errorf("Fetch() = %s, want the attested predicate", got)
			}
		})
	}
}

// pushImage pushes a random image to a new in-memory registry and returns its digest.
func pushImage(t *testing.T) name.Digest {
	t.Helper()
	srv := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(srv.Close)
	img, err := random.Image(64, 1)
	if err != nil {
		t.Fatal(err)
	}
	tag, err := name.NewTag(strings.TrimPrefix(srv.URL, "http://") + "/nais/app:latest")
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(tag, img); err != nil {
		t.Fatal(err)
	}
	h, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return tag.Context().Digest(h.String())
}

// attachBundle signs the statement in testdata/<s.statement>-statement.json, with its subject
// rewritten to digest, and attaches it to digest as a Sigstore bundle referrer.
func attachBundle(t *testing.T, vs *ca.VirtualSigstore, digest name.Digest, s signedStatement) {
	t.Helper()
	statement, err := os.ReadFile("testdata/" + s.statement + "-statement.json")
	if err != nil {
		t.Fatal(err)
	}
	h, err := v1.NewHash(digest.DigestStr())
	if err != nil {
		t.Fatal(err)
	}
	statement = bytes.ReplaceAll(statement, []byte(strings.Repeat("a", 64)), []byte(h.Hex))
	entity, err := vs.AttestAtTime(s.subject, s.issuer, statement, time.Now(), true)
	if err != nil {
		t.Fatal(err)
	}
	verification, err := entity.VerificationContent()
	if err != nil {
		t.Fatal(err)
	}
	sigContent, err := entity.SignatureContent()
	if err != nil {
		t.Fatal(err)
	}
	raw := sigContent.EnvelopeContent().RawEnvelope()
	envelope := &protodsse.Envelope{PayloadType: raw.PayloadType}
	if envelope.Payload, err = base64.StdEncoding.DecodeString(raw.Payload); err != nil {
		t.Fatal(err)
	}
	for _, sig := range raw.Signatures {
		decoded, err := base64.StdEncoding.DecodeString(sig.Sig)
		if err != nil {
			t.Fatal(err)
		}
		envelope.Signatures = append(envelope.Signatures, &protodsse.Signature{Sig: decoded, Keyid: sig.KeyID})
	}
	entries, err := entity.TlogEntries()
	if err != nil {
		t.Fatal(err)
	}
	entry := entries[0]
	// The entry does not expose its signed entry timestamp, so sign the same payload again.
	set, err := vs.RekorSignPayload(tlog.RekorPayload{
		Body:           entry.Body(),
		IntegratedTime: entry.IntegratedTime().Unix(),
		LogIndex:       entry.LogIndex(),
		LogID:          hex.EncodeToString([]byte(entry.LogKeyID())),
	})
	if err != nil {
		t.Fatal(err)
	}
	tle := entry.TransparencyLogEntry()
	tle.KindVersion = &protorekor.KindVersion{Kind: "dsse", Version: "0.0.1"}
	tle.InclusionPromise = &protorekor.InclusionPromise{SignedEntryTimestamp: set}
	mediaType, err := sgbundle.MediaTypeString("0.3")
	if err != nil {
		t.Fatal(err)
	}
	b, err := protojson.Marshal(&protobundle.Bundle{
		MediaType: mediaType,
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_Certificate{
				Certificate: &protocommon.X509Certificate{RawBytes: verification.Certificate().Raw},
			},
			TlogEntries: []*protorekor.TransparencyLogEntry{tle},
		},
		Content: &protobundle.Bundle_DsseEnvelope{DsseEnvelope: envelope},
	})
	if err != nil {
		t.Fatal(err)
	}
	var predicateType struct {
		PredicateType string `json:"predicateType"`
	}
	if err := json.Unmarshal(statement, &predicateType); err != nil {
		t.Fatal(err)
	}
	if err := ociremote.WriteAttestationNewBundleFormat(digest, b, predicateType.PredicateType); err != nil {
		t.Fatal(err)
	}
}

// legacyCheckOpts returns the options for verifying legacy-format attestations signed by a
// virtual Sigstore instance, whose certificates have no SCTs.
func legacyCheckOpts(t *testing.T, vs *ca.VirtualSigstore, identities ...cosign.Identity) *cosign.CheckOpts {
	t.Helper()
	f := &Fetcher{keychain: authn.DefaultKeychain, trustedRoot: vs, identities: identities, ignoreSCT: true}
	co := f.checkOpts(t.Context())
	co.NewBundleFormat = false
	return co
}

// TestCheckOptsAcceptLegacyEmailSigner verifies real legacy-format signatures from a virtual
// Sigstore instance against the identities of a fetcher trusting GitHub organization nais and
// email domain nav.no.
func TestCheckOptsAcceptLegacyEmailSigner(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	statement, err := os.ReadFile("testdata/cyclonedx-statement.json")
	if err != nil {
		t.Fatal(err)
	}
	email, err := EmailSigners{Issuer: GoogleIssuer, Domains: []string{"nav.no"}}.identity()
	if err != nil {
		t.Fatal(err)
	}
	co := legacyCheckOpts(t, vs, githubIdentity([]string{"nais"}), email)
	h, err := v1.NewHash("sha256:" + strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name, subject, issuer string
		wantErr               bool
	}{
		{name: "trusted domain", subject: "ola.nordmann@nav.no", issuer: GoogleIssuer},
		{name: "untrusted domain", subject: "ola@evil.com", issuer: GoogleIssuer, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entity, err := vs.Attest(tt.subject, tt.issuer, statement)
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = cosign.VerifyImageAttestation(t.Context(), legacyAttestations(t, vs, entity), h, co)
			if tt.wantErr && err == nil {
				t.Fatal("VerifyImageAttestation() succeeded, want error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("VerifyImageAttestation(): %v", err)
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

	co := legacyCheckOpts(t, vs, githubIdentity([]string{"nais"}))

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
