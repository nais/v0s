package grpcapi

import (
	"testing"
	"time"

	v0sv1 "github.com/nais/v0s/api/v0s/v1"
	"github.com/nais/v0s/internal/v0s"
)

func TestImageToProtoSafeFetchErrors(t *testing.T) {
	raw := "-----BEGIN CERTIFICATE----- historical payload -----END CERTIFICATE----- email=builder@example.com issuer=https://issuer.example.com"
	for _, tc := range []struct {
		name    string
		state   v0s.SBOMState
		code    v0s.ImageErrorCode
		scanned time.Time
		message string
		status  v0sv1.ImageStatus
	}{
		{"missing", v0s.SBOMMissing, v0s.ImageErrorCodeUnspecified, time.Time{}, "No SBOM attestation was found", v0sv1.ImageStatus_IMAGE_STATUS_NO_SBOM},
		{"failed", v0s.SBOMFailed, v0s.ImageErrorCodeUnspecified, time.Time{}, "Fetching SBOM failed", v0sv1.ImageStatus_IMAGE_STATUS_FAILED},
		{"rejected", v0s.SBOMFailed, v0s.ImageErrorCodeAttestationRejected, time.Time{}, "SBOM attestation was rejected", v0sv1.ImageStatus_IMAGE_STATUS_FAILED},
		{"scan failure", v0s.SBOMFetched, v0s.ImageErrorCodeUnspecified, time.Time{}, raw, v0sv1.ImageStatus_IMAGE_STATUS_FAILED},
		{"rescan failure", v0s.SBOMFetched, v0s.ImageErrorCodeUnspecified, time.Unix(100, 0), raw, v0sv1.ImageStatus_IMAGE_STATUS_SCANNED},
	} {
		t.Run(tc.name, func(t *testing.T) {
			img := imageToProto(v0s.Image{SBOMState: tc.state, Error: raw, ErrorCode: tc.code, ScannedAt: tc.scanned})
			if img.GetError() != tc.message || img.GetStatus() != tc.status {
				t.Errorf("image=%v; want error=%q, status=%s", img, tc.message, tc.status)
			}
			if tc.code == v0s.ImageErrorCodeAttestationRejected && img.GetErrorCode() != v0sv1.ImageErrorCode_IMAGE_ERROR_CODE_ATTESTATION_REJECTED {
				t.Errorf("rejected classification lost: %v", img)
			}
		})
	}
}
