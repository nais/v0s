package purl_test

import (
	"testing"

	"github.com/nais/v0s/internal/purl"
)

func TestPackageKey(t *testing.T) {
	tests := []struct {
		in, want string
		err      bool
	}{
		{in: "pkg:npm/%40scope/name@1.2.3", want: "pkg:npm/%40scope/name"},
		{in: "pkg:npm/@scope/name@1.2.3", want: "pkg:npm/%40scope/name"},
		{in: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar", want: "pkg:maven/org.apache.logging.log4j/log4j-core"},
		{in: "pkg:deb/debian/openssl@3.0.11-1~deb12u2?arch=amd64&distro=debian-12", want: "pkg:deb/debian/openssl"},
		{in: "pkg:golang/github.com/foo/bar@v1.2.3#sub/dir", want: "pkg:golang/github.com/foo/bar"},
		{in: "pkg:npm/leftpad", want: "pkg:npm/leftpad"},
		{in: "not a purl", err: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := purl.PackageKey(tt.in)
			if tt.err {
				if err == nil {
					t.Fatalf("PackageKey(%q) = %q, want error", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("PackageKey(%q) = %q, want %q", tt.in, got, tt.want)
			}
			// Keys are fixed points: a key's key is itself.
			again, err := purl.PackageKey(got)
			if err != nil || again != got {
				t.Errorf("PackageKey(%q) = %q, %v; want idempotent", got, again, err)
			}
		})
	}
}
