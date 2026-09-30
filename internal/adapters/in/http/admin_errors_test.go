package http

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"sprezz-identity/internal/domain/port"

	"github.com/stretchr/testify/assert"
)

func TestAdminErrorStatus(t *testing.T) {
	verr := port.NewValidationError()
	verr.Add("allowed_idps", "at least one sign-in method is required")

	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantSafe   bool
	}{
		{name: "validation", err: verr, wantStatus: http.StatusUnprocessableEntity},
		{name: "wrapped validation", err: fmt.Errorf("wrap: %w", verr), wantStatus: http.StatusUnprocessableEntity},
		{name: "system managed", err: port.ErrSystemManaged, wantStatus: http.StatusForbidden},
		{name: "wrapped system managed", err: fmt.Errorf("wrap: %w", port.ErrSystemManaged), wantStatus: http.StatusForbidden},
		{name: "in use", err: port.ErrInUse, wantStatus: http.StatusConflict},
		{name: "application not found", err: port.ErrApplicationNotFound, wantStatus: http.StatusNotFound},
		{name: "group not found", err: fmt.Errorf("wrap: %w", port.ErrGroupNotFound), wantStatus: http.StatusNotFound},
		{name: "profile not found", err: port.ErrProfileNotFound, wantStatus: http.StatusNotFound},
		{name: "tenant not found", err: port.ErrTenantNotFound, wantStatus: http.StatusNotFound},
		{name: "unknown errors are sanitized", err: errors.New("pq: password authentication failed for user admin"), wantStatus: http.StatusInternalServerError, wantSafe: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, message := adminErrorStatus(tt.err)
			assert.Equal(t, tt.wantStatus, status)
			assert.NotEmpty(t, message)
			if tt.wantSafe {
				assert.NotContains(t, message, "password", "internal error text must never reach the browser")
			}
		})
	}
}
