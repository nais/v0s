package v0s_test

import (
	"testing"
	"time"

	"github.com/nais/v0s"
)

func TestImageStatus(t *testing.T) {
	scanned := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		img  v0s.Image
		want v0s.ImageStatus
	}{
		{"not fetched", v0s.Image{SBOMState: v0s.SBOMPending}, v0s.ImagePending},
		{"no attestation", v0s.Image{SBOMState: v0s.SBOMMissing, Error: "none"}, v0s.ImageNoSBOM},
		{"fetch failed", v0s.Image{SBOMState: v0s.SBOMFailed, Error: "timeout"}, v0s.ImageFailed},
		{"fetched, not scanned", v0s.Image{SBOMState: v0s.SBOMFetched}, v0s.ImagePending},
		{"scan failed", v0s.Image{SBOMState: v0s.SBOMFetched, Error: "bad sbom"}, v0s.ImageFailed},
		{"scanned", v0s.Image{SBOMState: v0s.SBOMFetched, ScannedAt: scanned}, v0s.ImageScanned},
		{"rescan failed", v0s.Image{SBOMState: v0s.SBOMFetched, ScannedAt: scanned, Error: "oom"}, v0s.ImageScanned},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.img.Status(); got != tt.want {
				t.Errorf("Status() = %q, want %q", got, tt.want)
			}
		})
	}
}
