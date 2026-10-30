package attest

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"testing"
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
