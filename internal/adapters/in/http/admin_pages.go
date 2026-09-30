package http

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"
	"sprezz-identity/internal/views/admin"

	"github.com/a-h/templ"
	"github.com/google/uuid"
)

// headerAdminFragment marks a response that is a card fragment, even though its status is not 2xx. The admin
// script swaps such responses in instead of discarding them.
const headerAdminFragment = "X-Admin-Fragment"

// isPartialRequest reports whether the browser asked for a fragment (an htmx navigation) rather than a full page.
// History restores after a cache miss come from htmx too, but they need the whole document.
func isPartialRequest(r *http.Request) bool {
	return r.Header.Get(model.HeaderHxRequest) == "true" && r.Header.Get("HX-History-Restore-Request") != "true"
}

// renderAdminPage renders the fragment for htmx navigations and the full page for everything else, so every
// admin URL can be opened, refreshed and bookmarked directly.
func (h *HttpAdapter) renderAdminPage(w http.ResponseWriter, r *http.Request, content, page templ.Component) {
	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	w.Header().Add("Vary", model.HeaderHxRequest)
	if isPartialRequest(r) {
		_ = content.Render(r.Context(), w)
		return
	}
	_ = page.Render(r.Context(), w)
}

// renderFragment renders a component with the given status, flagged so the admin script swaps it in.
func (h *HttpAdapter) renderFragment(w http.ResponseWriter, r *http.Request, status int, c templ.Component) {
	w.Header().Set(model.HeaderContentType, model.ContentTypeHTML)
	if status != http.StatusOK {
		w.Header().Set(headerAdminFragment, "true")
	}
	w.WriteHeader(status)
	_ = c.Render(r.Context(), w)
}

// redirectTo sends an htmx request to a new URL with a full navigation, or a plain redirect otherwise.
func redirectTo(w http.ResponseWriter, r *http.Request, target string) {
	if r.Header.Get(model.HeaderHxRequest) == "true" {
		w.Header().Set(model.HeaderHxRedirect, target)
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// flashURL appends a success message to a path.
func flashURL(path, msg string) string {
	return path + "?msg=" + strings.ReplaceAll(msg, " ", "+")
}

// sectionResultFor converts a save outcome into what a card renders: field errors, a general message and the
// HTTP status. Domain errors never leak their raw text.
func sectionResultFor(err error) (admin.SectionResult, int) {
	if err == nil {
		return admin.SectionResult{Saved: true}, http.StatusOK
	}
	var verr *port.ValidationError
	if errors.As(err, &verr) {
		return admin.SectionResult{Errors: verr.Fields, Error: generalValidationMessage(verr)}, http.StatusUnprocessableEntity
	}
	status, message := adminErrorStatus(err)
	return admin.SectionResult{Error: message}, status
}

// generalValidationMessage shows a summary above the fields when any of them failed.
func generalValidationMessage(verr *port.ValidationError) string {
	if len(verr.Fields) > 1 {
		return "Some values need attention."
	}
	return ""
}

// parseUUIDList parses submitted identifiers; a malformed one is reported against the field instead of dropped.
func parseUUIDList(values []string, field string, errs map[string]string) []uuid.UUID {
	out := []uuid.UUID{}
	for _, raw := range CleanBoundaryStringSlice(append([]string{}, values...)) {
		id, err := uuid.Parse(raw)
		if err != nil {
			errs[field] = "one or more selected values are invalid"
			continue
		}
		out = append(out, id)
	}
	return out
}

// parseOptionalUUID parses an optional identifier; an empty value means "none".
func parseOptionalUUID(raw, field string, errs map[string]string) *uuid.UUID {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		errs[field] = "the selected value is invalid"
		return nil
	}
	return &id
}

// mergeFieldErrors copies the field messages of a validation error into the form's error map.
func mergeFieldErrors(err error, errs map[string]string) {
	var verr *port.ValidationError
	if errors.As(err, &verr) {
		for field, message := range verr.Fields {
			errs[field] = message
		}
	}
}

// parseBodyForm reads a url-encoded form body for any method. net/http only parses request bodies for POST, PUT
// and PATCH, so a DELETE that carries a typed confirmation would otherwise arrive with an empty form.
func parseBodyForm(r *http.Request) error {
	if r.Method == http.MethodDelete && r.Body != nil && strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		body, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, 1<<20))
		if err != nil {
			return err
		}
		values, err := url.ParseQuery(string(body))
		if err != nil {
			return err
		}
		if r.Form == nil {
			r.Form = url.Values{}
		}
		for key, vals := range values {
			r.Form[key] = append(r.Form[key], vals...)
		}
		return nil
	}
	return r.ParseForm()
}
