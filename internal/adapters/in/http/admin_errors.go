package http

import (
	"errors"
	"log/slog"
	"net/http"

	"sprezz-identity/internal/domain/port"
)

// adminErrorStatus translates a domain error into an HTTP status code and a message that is safe to show
// to an administrator. Unknown errors are reported generically so internal details never reach the browser.
func adminErrorStatus(err error) (int, string) {
	var validationErr *port.ValidationError

	switch {
	case errors.As(err, &validationErr):
		return http.StatusUnprocessableEntity, validationErr.Error()
	case errors.Is(err, port.ErrSystemManaged):
		return http.StatusForbidden, port.ErrSystemManaged.Error()
	case errors.Is(err, port.ErrInUse):
		return http.StatusConflict, port.ErrInUse.Error()
	case errors.Is(err, port.ErrApplicationNotFound):
		return http.StatusNotFound, port.ErrApplicationNotFound.Error()
	case errors.Is(err, port.ErrGroupNotFound):
		return http.StatusNotFound, port.ErrGroupNotFound.Error()
	case errors.Is(err, port.ErrProfileNotFound):
		return http.StatusNotFound, port.ErrProfileNotFound.Error()
	case errors.Is(err, port.ErrTenantNotFound):
		return http.StatusNotFound, port.ErrTenantNotFound.Error()
	default:
		return http.StatusInternalServerError, "an unexpected error occurred"
	}
}

// renderDomainError logs the underlying failure and renders the mapped, sanitized error page.
func (h *HttpAdapter) renderDomainError(w http.ResponseWriter, r *http.Request, err error) {
	status, message := adminErrorStatus(err)
	if status >= http.StatusInternalServerError {
		slog.Error("admin request failed", "path", r.URL.Path, "err", err)
	}
	h.renderError(w, r, status, message)
}
