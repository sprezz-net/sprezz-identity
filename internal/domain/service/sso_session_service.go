package service

import (
	"context"
	"errors"
	"strings"

	"sprezz-identity/internal/domain/port"
)

type SSOSessionService struct {
	storage port.Storage
	appEnv  string
}

func NewSSOSessionService(s port.Storage, appEnv string) *SSOSessionService {
	return &SSOSessionService{storage: s, appEnv: appEnv}
}

// BuildSessionCookie enforces partition namespacing and environmental security prefix gates [8.3, 8.3.1, 8.3.2]
func (s *SSOSessionService) BuildSessionCookie(ctx context.Context, cmd port.CookieIntentCommand) (*port.CookieIntentResponse, error) {
	// 1. Resolve internal Partition metadata to pull its canonical text alias name [3.1]
	partition, err := s.storage.GetPartitionByID(ctx, cmd.TenantID, cmd.PartitionID)
	if err != nil {
		return nil, port.ErrPartitionNotFound
	}

	// 2. Calculate dynamic partition matrix namespacing footprint
	cookieName := "spz_session_" + partition.AliasName

	// 3. Evaluate network guards and local development environment exception loops [8.3]
	isLocalhost := cmd.RequestHost == "localhost" || strings.HasPrefix(cmd.RequestHost, "127.0.0.1")
	useSecureTransport := true

	if s.appEnv == "local" && isLocalhost {
		useSecureTransport = false // Local unencrypted debugging loop permitted [8.3]
	} else {
		// Production/Staging: Enforce watertight domain-locked prefix isolation wrappers [8.3]
		cookieName = "__Host-" + cookieName
	}

	// 4. Bind transient lifecycle string namespace prefixes
	var finalizedValue string
	maxAge := 86400 // 24 Hours absolute default expiration threshold

	switch cmd.LifecycleStage {
	case "handshake":
		finalizedValue = "handshake:" + cmd.PayloadValue
		maxAge = 300 // 5 Minute pre-auth interaction staging restriction [4.1]
	case "bearer":
		finalizedValue = "bearer:" + cmd.PayloadValue
	case "clear":
		finalizedValue = ""
		maxAge = -1 // Direct browser eviction trigger [7.3]
	default:
		return nil, errors.New("sso_cookie_service: invalid token lifecycle stage identifier")
	}

	return &port.CookieIntentResponse{
		CookieName:  cookieName,
		CookieValue: finalizedValue,
		MaxAge:      maxAge,
		Secure:      useSecureTransport,
	}, nil
}

// ParseSessionCookie dissects an incoming browser cookie payload string,
// peeling back transient prefix state identifiers safely at the perimeter boundary.
func (s *SSOSessionService) ParseSessionCookie(ctx context.Context, cookieValue string) (string, string, error) {
	if cookieValue == "" {
		return "", "", errors.New("sso_cookie_service: cannot parse an empty or missing token string value")
	}

	// 1. Locate the structural slice boundary marker separating state labels from underlying payloads
	idx := strings.Index(cookieValue, ":")
	if idx == -1 {
		return "", "", errors.New("sso_cookie_service: corrupt or non-namespaced authentication session string")
	}

	stage := cookieValue[:idx]
	payload := cookieValue[idx+1:]

	// 2. Structural Security Guard: Assert that parsed parameters fall strictly within known design buckets
	if stage != "handshake" && stage != "bearer" {
		return "", "", errors.New("sso_cookie_service: incoming token carries an unrecognized lifecycle header state")
	}

	if payload == "" {
		return "", "", errors.New("sso_cookie_service: authentication payload context string is blank")
	}

	return stage, payload, nil
}
