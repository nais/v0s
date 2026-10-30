// Package purl derives package keys from package URLs.
package purl

import (
	"fmt"

	"github.com/package-url/packageurl-go"
)

// PackageKey returns the purl with version, qualifiers and subpath removed,
// in canonical form. Two versions of the same package have the same key.
//
//	pkg:npm/%40scope/name@1.2.3           -> pkg:npm/%40scope/name
//	pkg:deb/debian/openssl@3.0?arch=amd64 -> pkg:deb/debian/openssl
func PackageKey(s string) (string, error) {
	p, err := packageurl.FromString(s)
	if err != nil {
		return "", fmt.Errorf("parsing purl: %w", err)
	}
	p.Version = ""
	p.Qualifiers = nil
	p.Subpath = ""
	return p.ToString(), nil
}
