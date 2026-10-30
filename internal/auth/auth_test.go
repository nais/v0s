package auth

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"google.golang.org/api/idtoken"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestUnaryInterceptor(t *testing.T) {
	const audience = "v0s"

	// fakeValidate accepts the token "good-<email>" for audience and returns <email> as the email claim.
	fakeValidate := func(_ context.Context, token, aud string) (*idtoken.Payload, error) {
		if aud != audience {
			return nil, errors.New("wrong audience")
		}
		email, ok := strings.CutPrefix(token, "good-")
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
		{name: "allowed", authorization: []string{"Bearer good-slsa@nais-io.iam.gserviceaccount.com"}, want: codes.OK},
		{name: "allowed without suffix in allowlist", authorization: []string{"Bearer good-console@nais-io.iam.gserviceaccount.com"}, want: codes.OK},
		{name: "lowercase scheme", authorization: []string{"bearer good-slsa@nais-io.iam.gserviceaccount.com"}, want: codes.OK},
		{name: "no metadata", want: codes.Unauthenticated},
		{name: "not bearer", authorization: []string{"Basic good-slsa@nais-io.iam.gserviceaccount.com"}, want: codes.Unauthenticated},
		{name: "invalid token", authorization: []string{"Bearer forged"}, want: codes.Unauthenticated},
		{name: "no email claim", authorization: []string{"Bearer good-"}, want: codes.Unauthenticated},
		{name: "email not allowed", authorization: []string{"Bearer good-other@nais-io.iam.gserviceaccount.com"}, want: codes.PermissionDenied},
		{name: "allowlist entry is not a domain wildcard", authorization: []string{"Bearer good-console@nais-io"}, want: codes.PermissionDenied},
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
