package attest

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	cbundle "github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v3/pkg/oci"
	"github.com/sigstore/cosign/v3/pkg/oci/empty"
	"github.com/sigstore/cosign/v3/pkg/oci/mutate"
	"github.com/sigstore/cosign/v3/pkg/oci/static"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/tlog"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

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
