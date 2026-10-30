// Package auth authenticates gRPC callers with Google-signed ID tokens.
package auth

import (
	"context"
	"log/slog"
	"slices"
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

func newUnaryInterceptor(validate validateFunc, audience string, serviceAccounts []string, log *slog.Logger) grpc.UnaryServerInterceptor {
	allowed := make([]string, len(serviceAccounts))
	for i, sa := range serviceAccounts {
		if !strings.HasSuffix(sa, serviceAccountSuffix) {
			sa += serviceAccountSuffix
		}
		allowed[i] = sa
	}

	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		log := log.With("method", info.FullMethod)

		token, ok := bearerToken(ctx)
		if !ok {
			log.Warn("missing bearer token")
			return nil, status.Error(codes.Unauthenticated, "missing bearer token")
		}
		payload, err := validate(ctx, token, audience)
		if err != nil {
			log.With("err", err).Warn("invalid token")
			return nil, status.Error(codes.Unauthenticated, "invalid token")
		}
		email, _ := payload.Claims["email"].(string)
		if email == "" {
			log.Warn("token has no email claim")
			return nil, status.Error(codes.Unauthenticated, "token has no email claim")
		}
		if !slices.Contains(allowed, email) {
			log.With("email", email).Warn("service account not allowed")
			return nil, status.Error(codes.PermissionDenied, "service account not allowed")
		}
		return handler(ctx, req)
	}
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
