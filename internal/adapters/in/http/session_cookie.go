package http

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
)

// sessionCookiePrefix starts the name of every partition session cookie; production adds the __Host- prefix.
const sessionCookiePrefix = "spz_session_"

// writeSessionCookie sets a partition cookie from the intent the domain computed.
func writeSessionCookie(w http.ResponseWriter, intent *port.CookieIntentResponse) {
	http.SetCookie(w, &http.Cookie{
		Name:     intent.CookieName,
		Value:    intent.CookieValue,
		Path:     "/",
		MaxAge:   intent.MaxAge,
		HttpOnly: true,
		Secure:   intent.Secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// sessionFromCookie resolves the live SSO session carried by the cookie with this name. It returns nil when the
// cookie is missing or is not a live session (unknown, expired, idle, signed out, another tenant).
func sessionFromCookie(r *http.Request, sso port.SSOSessionUseCase, tenantID uuid.UUID, cookieName string) *model.SSOSession {
	cookie, err := r.Cookie(cookieName)
	if err != nil || cookie.Value == "" {
		return nil
	}

	session, err := sso.ResolveSession(r.Context(), tenantID, cookie.Value)
	if err != nil {
		if !errors.Is(err, port.ErrSessionNotFound) && !errors.Is(err, port.ErrTenantInactive) {
			slog.Error("session lookup failed", "err", err)
		}
		return nil
	}
	return session
}

// sessionCookieName resolves the cookie name of a partition (0 means the tenant's default partition).
func sessionCookieName(r *http.Request, sso port.SSOSessionUseCase, tenantID uuid.UUID, partitionID int64) (*port.CookieIntentResponse, error) {
	return sso.BuildSessionCookie(r.Context(), port.CookieIntentCommand{
		TenantID:       tenantID,
		PartitionID:    partitionID,
		LifecycleStage: "clear", // only used to learn the namespaced name and flags
		RequestHost:    r.Host,
	})
}

// foundSession is a live session together with the cookie that carried it.
type foundSession struct {
	session *model.SSOSession
	cookie  *http.Cookie
}

// anyPartitionSession finds the live session of the request across every partition cookie. Non-default partitions
// (such as the administrative one) are tried first, then the default partition.
func anyPartitionSession(r *http.Request, sso port.SSOSessionUseCase, tenantID uuid.UUID) *foundSession {
	defaultName := ""
	if spec, err := sessionCookieName(r, sso, tenantID, 0); err == nil {
		defaultName = spec.CookieName
	}

	for _, cookie := range r.Cookies() {
		if cookie.Name == defaultName || !isSessionCookieName(cookie.Name) {
			continue
		}
		if session := sessionFromCookie(r, sso, tenantID, cookie.Name); session != nil {
			return &foundSession{session: session, cookie: cookie}
		}
	}

	if defaultName == "" {
		return nil
	}
	if cookie, err := r.Cookie(defaultName); err == nil {
		if session := sessionFromCookie(r, sso, tenantID, defaultName); session != nil {
			return &foundSession{session: session, cookie: cookie}
		}
	}
	return nil
}

func isSessionCookieName(name string) bool {
	return strings.HasPrefix(strings.TrimPrefix(name, "__Host-"), sessionCookiePrefix)
}

// requestCookies hands the cookies of a request to the domain by name. The domain picks the one of the partition.
func requestCookies(r *http.Request) map[string]string {
	cookies := make(map[string]string)
	for _, c := range r.Cookies() {
		if isSessionCookieName(c.Name) {
			cookies[c.Name] = c.Value
		}
	}
	return cookies
}
