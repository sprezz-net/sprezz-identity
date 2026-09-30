package http

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
)

// AdminSessionContextKey stores the verified administrator of the current request.
const AdminSessionContextKey ContextKey = "spz_admin_session"

// AdminSession identifies the authenticated administrator behind an /admin request.
type AdminSession struct {
	UserID      uuid.UUID
	PartitionID int64
}

// AdminSessionFromContext recovers the verified administrator set by requireAdminSession.
func AdminSessionFromContext(ctx context.Context) (*AdminSession, bool) {
	session, ok := ctx.Value(AdminSessionContextKey).(*AdminSession)
	return session, ok
}

type adminSessionState int

const (
	// adminSessionMissing means there is no usable session and the administrator must sign in.
	adminSessionMissing adminSessionState = iota
	// adminSessionDenied means the session is genuine but the account may not log in (blocked, deactivated, ...).
	adminSessionDenied
	// adminSessionValid means the request belongs to an active administrator.
	adminSessionValid
)

type adminSessionResult struct {
	state      adminSessionState
	session    *AdminSession
	cookieName string
}

// resolveAdminSession verifies the session cookie of the tenant's administrative partition.
// The user is looked up by ID, so a cookie naming an unknown user never passes.
func (h *HttpAdapter) resolveAdminSession(r *http.Request, tenant *model.Tenant) (*adminSessionResult, error) {
	partition, err := h.storagePort.GetPartitionByAlias(r.Context(), tenant.ID, model.AdminPartitionAliasName)
	if err != nil {
		return nil, err
	}

	cookieSpec, err := h.ssoUseCase.BuildSessionCookie(r.Context(), port.CookieIntentCommand{
		TenantID:       tenant.ID,
		PartitionID:    partition.ID,
		LifecycleStage: "clear", // Resolves the namespaced bearer cookie name
		RequestHost:    r.Host,
	})
	if err != nil {
		return nil, err
	}

	cookie, err := r.Cookie(cookieSpec.CookieName)
	if err != nil || cookie.Value == "" {
		return &adminSessionResult{state: adminSessionMissing}, nil
	}

	userID, ok := h.parseAdminBearer(r.Context(), cookie.Value, partition.ID)
	if !ok {
		return &adminSessionResult{state: adminSessionMissing, cookieName: cookieSpec.CookieName}, nil
	}

	return h.verifyAdminProfile(r.Context(), tenant.ID, userID, partition.ID, cookieSpec.CookieName)
}

// verifyAdminProfile checks that the user named by the cookie exists in the admin partition and may log in.
func (h *HttpAdapter) verifyAdminProfile(ctx context.Context, tenantID, userID uuid.UUID, partitionID int64, cookieName string) (*adminSessionResult, error) {
	profile, err := h.storagePort.GetUserProfileByIDAndPartitionAlias(ctx, tenantID, model.AdminPartitionAliasName, userID)
	if errors.Is(err, port.ErrUserProfileNotFound) {
		slog.Warn("admin session names an unknown user", "user_id", userID, "tenant_id", tenantID)
		return &adminSessionResult{state: adminSessionMissing, cookieName: cookieName}, nil
	}
	if err != nil {
		return nil, err
	}

	if allowed, loginErr := profile.IsLoginAllowed(); !allowed || loginErr != nil {
		slog.Warn("admin session rejected: login not allowed", "user_id", userID, "err", loginErr)
		return &adminSessionResult{state: adminSessionDenied, cookieName: cookieName}, nil
	}

	return &adminSessionResult{
		state:   adminSessionValid,
		session: &AdminSession{UserID: profile.ID, PartitionID: partitionID},
	}, nil
}

// parseAdminBearer extracts the user ID from a "bearer:<userUUID>:<partitionID>" cookie and checks that the
// cookie was issued for the administrative partition.
func (h *HttpAdapter) parseAdminBearer(ctx context.Context, cookieValue string, partitionID int64) (uuid.UUID, bool) {
	stage, payload, err := h.ssoUseCase.ParseSessionCookie(ctx, cookieValue)
	if err != nil || stage != "bearer" {
		return uuid.Nil, false
	}

	parts := strings.Split(payload, ":")
	if len(parts) != 2 {
		return uuid.Nil, false
	}

	userID, err := uuid.Parse(parts[0])
	if err != nil {
		return uuid.Nil, false
	}

	cookiePartition, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || cookiePartition != partitionID {
		return uuid.Nil, false
	}
	return userID, true
}

// isCrossSiteStateChange reports whether a state-changing request originates from another site.
// Browsers send Sec-Fetch-Site on every request; Origin is checked as a fallback for older clients.
func isCrossSiteStateChange(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}

	if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
		return site != "same-origin" && site != "none"
	}

	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return true
	}
	return parsed.Host != r.Host
}
