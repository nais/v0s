// Package auth authenticates gRPC callers with Google-signed ID tokens.
package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"slices"
	"strconv"
	"strings"

	"google.golang.org/api/idtoken"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const serviceAccountSuffix = ".iam.gserviceaccount.com"

// validateFunc verifies an ID token's signature, expiry and audience.
type validateFunc func(ctx context.Context, token, audience string) (*idtoken.Payload, error)

// UnaryInterceptor returns an interceptor that accepts only requests carrying
// "authorization: Bearer <token>", where the token is a Google-signed ID token
// for audience whose email claim is one of serviceAccounts.
//
// Entries in serviceAccounts may omit the ".iam.gserviceaccount.com" suffix.
func UnaryInterceptor(audience string, serviceAccounts []string, log *slog.Logger) grpc.UnaryServerInterceptor {
	return newUnaryInterceptor(idtoken.Validate, audience, serviceAccounts, log)
}

// StreamInterceptor is UnaryInterceptor for streaming RPCs.
func StreamInterceptor(audience string, serviceAccounts []string, log *slog.Logger) grpc.StreamServerInterceptor {
	authenticate := newAuthenticator(idtoken.Validate, audience, serviceAccounts, log)
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := authenticate(ss.Context(), info.FullMethod); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}

func newUnaryInterceptor(validate validateFunc, audience string, serviceAccounts []string, log *slog.Logger) grpc.UnaryServerInterceptor {
	authenticate := newAuthenticator(validate, audience, serviceAccounts, log)
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if err := authenticate(ctx, info.FullMethod); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// newAuthenticator returns a function that returns nil if the caller of method is allowed, and
// an Unauthenticated or PermissionDenied status error otherwise.
func newAuthenticator(validate validateFunc, audience string, serviceAccounts []string, log *slog.Logger) func(ctx context.Context, method string) error {
	allowed := make([]string, len(serviceAccounts))
	for i, sa := range serviceAccounts {
		if !strings.HasSuffix(sa, serviceAccountSuffix) {
			sa += serviceAccountSuffix
		}
		allowed[i] = sa
	}

	return func(ctx context.Context, method string) error {
		log := log.With("method", method)

		token, ok := bearerToken(ctx)
		if !ok {
			log.Warn("missing bearer token")
			return status.Error(codes.Unauthenticated, "missing bearer token")
		}
		// Service account ID tokens are RS256. The pinned validator panics on
		// some malformed ES256 tokens, so other algorithms never reach it.
		if alg := tokenAlgorithm(token); alg != "RS256" {
			log.With("alg", strconv.Quote(alg)).Warn("unsupported token algorithm")
			return status.Error(codes.Unauthenticated, "invalid token")
		}
		payload, err := validate(ctx, token, audience)
		if err != nil {
			log.With("err", err).Warn("invalid token")
			return status.Error(codes.Unauthenticated, "invalid token")
		}
		email, _ := payload.Claims["email"].(string)
		if email == "" {
			log.Warn("token has no email claim")
			return status.Error(codes.Unauthenticated, "token has no email claim")
		}
		if !slices.Contains(allowed, email) {
			log.With("email", email).Warn("service account not allowed")
			return status.Error(codes.PermissionDenied, "service account not allowed")
		}
		return nil
	}
}

// tokenAlgorithm returns the "alg" of a JWT's header, or "" if the header is malformed.
func tokenAlgorithm(token string) string {
	segment, _, _ := strings.Cut(token, ".")
	b, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return ""
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(b, &header); err != nil {
		return ""
	}
	return header.Alg
}

// bearerToken returns the token from the incoming "authorization" metadata.
func bearerToken(ctx context.Context) (string, bool) {
	values := metadata.ValueFromIncomingContext(ctx, "authorization")
	if len(values) == 0 {
		return "", false
	}
	scheme, token, ok := strings.Cut(values[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return "", false
	}
	return token, true
}
