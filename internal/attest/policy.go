package attest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v3/pkg/cosign"
)

type IdentityRule struct {
	Issuer        string   `json:"issuer"`
	SubjectRegExp string   `json:"subjectRegExp"`
	Repositories  []string `json:"repositories"`
}

func ParseIdentityRules(value string) ([]IdentityRule, error) {
	if value == "" {
		return nil, nil
	}
	var rules []IdentityRule
	dec := json.NewDecoder(bytes.NewBufferString(value))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rules); err != nil {
		return nil, fmt.Errorf("parsing attestation identity rules: %w", err)
	}
	if rules == nil {
		return nil, errors.New("attestation identity rules must be a JSON array")
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return nil, errors.New("attestation identity rules must be one JSON array")
	}
	if err := validateIdentityRules(rules); err != nil {
		return nil, err
	}
	return rules, nil
}

func validateIdentityRules(rules []IdentityRule) error {
	for i, rule := range rules {
		issuer, err := url.Parse(rule.Issuer)
		if err != nil || issuer.Scheme != "https" || issuer.Host == "" || issuer.User != nil || issuer.RawQuery != "" || issuer.Fragment != "" {
			return fmt.Errorf("attestation identity rule %d: issuer must be an exact HTTPS URL", i)
		}
		if rule.SubjectRegExp == "" {
			return fmt.Errorf("attestation identity rule %d: subjectRegExp is required", i)
		}
		if _, err := regexp.Compile(anchoredSubject(rule.SubjectRegExp)); err != nil {
			return fmt.Errorf("attestation identity rule %d: invalid subjectRegExp: %w", i, err)
		}
		if len(rule.Repositories) == 0 {
			return fmt.Errorf("attestation identity rule %d: repositories must not be empty", i)
		}
		for _, scope := range rule.Repositories {
			repo, err := name.NewRepository(scope, name.StrictValidation)
			if err != nil || repo.Name() != scope || strings.ContainsAny(scope, "@*") || strings.HasSuffix(scope, "/") {
				return fmt.Errorf("attestation identity rule %d: repository must be a canonical registry/path without tag, digest or wildcard: %q", i, scope)
			}
			for _, segment := range strings.Split(repo.RepositoryStr(), "/") {
				if segment == "" || segment == "." || segment == ".." {
					return fmt.Errorf("attestation identity rule %d: invalid repository path: %q", i, scope)
				}
			}
		}
	}
	return nil
}

func anchoredSubject(subject string) string {
	return `\A(?:` + subject + `)\z`
}

func (f *Fetcher) identities(repo name.Repository) []cosign.Identity {
	identities := []cosign.Identity{f.identity}
	for _, rule := range f.rules {
		for _, scope := range rule.Repositories {
			if repo.Name() == scope || strings.HasPrefix(repo.Name(), scope+"/") {
				identities = append(identities, cosign.Identity{
					Issuer: rule.Issuer, SubjectRegExp: anchoredSubject(rule.SubjectRegExp),
				})
				break
			}
		}
	}
	return identities
}
