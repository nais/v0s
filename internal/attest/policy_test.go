package attest

import (
	"encoding/json"
	"regexp"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
)

func TestParseIdentityRules(t *testing.T) {
	valid := `[{"issuer":"https://accounts.google.com","subjectRegExp":"[a-zA-Z0-9._%+-]+@nav\\.no","repositories":["europe-north1-docker.pkg.dev/nav-project/images"]}]`
	for _, tc := range []struct {
		value string
		valid bool
	}{
		{"", true},
		{"[]", true},
		{"null", false},
		{valid, true},
		{`[{"issuer":"https://accounts.google.com","subjectRegExp":".+"}]`, false},
		{`[{"subjectRegExp":".+","repositories":["ghcr.io/navikt"]}]`, false},
		{`[{"issuer":"https://accounts.google.com","subjectRegExp":"(","repositories":["ghcr.io/navikt"]}]`, false},
		{`[{"issuer":"https://accounts.google.com","subjectRegExp":".+","repositories":["navikt/app"]}]`, false},
		{`[{"issuer":"https://accounts.google.com","subjectRegExp":".+","repositories":["ghcr.io/navikt/app:latest"]}]`, false},
		{`[{"issuer":"https://accounts.google.com","subjectRegExp":".+","repositories":["ghcr.io/navikt/*"]}]`, false},
		{`[{"issuer":"https://accounts.google.com","subjectRegExp":".+","repositories":["ghcr.io/navikt"],"unknown":true}]`, false},
		{`[] []`, false},
		{`[{"issuer":"https://accounts.google.com","subjectRegExp":".+","repositories":["ghcr.io/navikt/../other"]}]`, false},
	} {
		t.Run(tc.value, func(t *testing.T) {
			_, err := ParseIdentityRules(tc.value)
			if (err == nil) != tc.valid {
				t.Fatalf("ParseIdentityRules: %v; valid=%v", err, tc.valid)
			}
		})
	}
	rules, err := ParseIdentityRules(valid)
	if err != nil {
		t.Fatal(err)
	}
	f := &Fetcher{identity: githubIdentity([]string{"nais"}), rules: rules}
	for _, tc := range []struct {
		repo string
		want int
	}{
		{"europe-north1-docker.pkg.dev/nav-project/images", 2},
		{"europe-north1-docker.pkg.dev/nav-project/images/team/app", 2},
		{"europe-north1-docker.pkg.dev/nav-project/images-evil/app", 1},
		{"europe-north1-docker.pkg.dev/other-project/images/app", 1},
		{"evil.example/nav-project/images", 1},
	} {
		repo, err := name.NewRepository(tc.repo)
		if err != nil {
			t.Fatal(err)
		}
		if got := len(f.identities(repo)); got != tc.want {
			t.Errorf("identities(%s)=%d, want %d", tc.repo, got, tc.want)
		}
	}
	re := regexp.MustCompile(anchoredSubject(rules[0].SubjectRegExp))
	for _, subject := range []string{"https://example.com/person@nav.no", "person@nav.no.evil", "person@sub.nav.no", "@nav.no", " person@nav.no", "person@nav.no\n"} {
		if re.MatchString(subject) {
			t.Errorf("unexpected match for %q", subject)
		}
	}
	encoded, err := json.Marshal(rules)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseIdentityRules(string(encoded)); err != nil {
		t.Fatal(err)
	}
}
