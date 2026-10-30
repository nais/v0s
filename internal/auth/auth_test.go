package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"google.golang.org/api/idtoken"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestUnaryInterceptor(t *testing.T) {
	const audience = "v0s"

	// fakeValidate accepts a token with payload "good-<email>" for audience and returns <email> as the email claim.
	fakeValidate := func(_ context.Context, token, aud string) (*idtoken.Payload, error) {
		if aud != audience {
			return nil, errors.New("wrong audience")
		}
		payload, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[1])
		if err != nil {
			return nil, err
		}
		email, ok := strings.CutPrefix(string(payload), "good-")
		if !ok {
			return nil, errors.New("bad signature")
		}
		return &idtoken.Payload{Claims: map[string]any{"email": email}}, nil
	}

	allowed := []string{"slsa@nais-io.iam.gserviceaccount.com", "console@nais-io"}

	tests := []struct {
		name          string
		authorization []string
		want          codes.Code
	}{
		{name: "allowed", authorization: []string{"Bearer " + jwt("RS256", "good-slsa@nais-io.iam.gserviceaccount.com")}, want: codes.OK},
		{name: "allowed without suffix in allowlist", authorization: []string{"Bearer " + jwt("RS256", "good-console@nais-io.iam.gserviceaccount.com")}, want: codes.OK},
		{name: "lowercase scheme", authorization: []string{"bearer " + jwt("RS256", "good-slsa@nais-io.iam.gserviceaccount.com")}, want: codes.OK},
		{name: "no metadata", want: codes.Unauthenticated},
		{name: "not bearer", authorization: []string{"Basic " + jwt("RS256", "good-slsa@nais-io.iam.gserviceaccount.com")}, want: codes.Unauthenticated},
		{name: "invalid token", authorization: []string{"Bearer " + jwt("RS256", "forged")}, want: codes.Unauthenticated},
		{name: "no email claim", authorization: []string{"Bearer " + jwt("RS256", "good-")}, want: codes.Unauthenticated},
		{name: "email not allowed", authorization: []string{"Bearer " + jwt("RS256", "good-other@nais-io.iam.gserviceaccount.com")}, want: codes.PermissionDenied},
		{name: "allowlist entry is not a domain wildcard", authorization: []string{"Bearer " + jwt("RS256", "good-console@nais-io")}, want: codes.PermissionDenied},
	}

	intercept := newUnaryInterceptor(fakeValidate, audience, allowed, slog.New(slog.NewTextHandler(io.Discard, nil)))
	info := &grpc.UnaryServerInfo{FullMethod: "/v0s.v1.VulnerabilityService/ListFindings"}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.authorization != nil {
				ctx = metadata.NewIncomingContext(ctx, metadata.MD{"authorization": tt.authorization})
			}
			called := false
			handler := func(context.Context, any) (any, error) {
				called = true
				return "ok", nil
			}
			_, err := intercept(ctx, nil, info, handler)
			if got := status.Code(err); got != tt.want {
				t.Fatalf("code = %v, want %v (err %v)", got, tt.want, err)
			}
			if called != (tt.want == codes.OK) {
				t.Errorf("handler called = %v, want %v", called, tt.want == codes.OK)
			}
		})
	}
}

// jwt returns an unsigned JWT with header alg and key ID "k1", and the given payload.
func jwt(alg, payload string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"`+alg+`","kid":"k1"}`)) + "." + enc([]byte(payload)) + "."
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// An ES256 token with a known key ID and a short signature panics in the
// pinned Google validator. The interceptor must reject it first.
func TestUnaryInterceptorRejectsES256(t *testing.T) {
	const audience = "v0s"
	jwks := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"keys":[{"kid":"k1","kty":"EC","crv":"P-256","x":"AQ","y":"AQ"}]}`)),
		}, nil
	})
	validator, err := idtoken.NewValidator(context.Background(), option.WithHTTPClient(&http.Client{Transport: jwks}))
	if err != nil {
		t.Fatal(err)
	}
	const email = "slsa@nais-io.iam.gserviceaccount.com"
	intercept := newUnaryInterceptor(validator.Validate, audience, []string{email}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	token := jwt("ES256", fmt.Sprintf(`{"aud":%q,"exp":%d,"email":%q}`, audience, time.Now().Add(time.Hour).Unix(), email))
	ctx := metadata.NewIncomingContext(context.Background(), metadata.MD{"authorization": {"Bearer " + token}})
	handler := func(context.Context, any) (any, error) { return "ok", nil }
	_, err = intercept(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/v0s.v1.VulnerabilityService/ListFindings"}, handler)
	if got := status.Code(err); got != codes.Unauthenticated {
		t.Errorf("code = %v, want Unauthenticated (err %v)", got, err)
	}
}
