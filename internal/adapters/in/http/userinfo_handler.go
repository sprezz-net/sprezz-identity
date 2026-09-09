package http

import (
	"encoding/json"
	"errors"
	"net/http"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/go-chi/chi/v5"
)

type UserInfoHandler struct {
	authUseCase port.AuthUseCase
}

func NewUserInfoHandler(auc port.AuthUseCase) *UserInfoHandler {
	return &UserInfoHandler{
		authUseCase: auc,
	}
}

func (h *UserInfoHandler) Routes(r chi.Router) {
	r.Get(port.RouteUserInfo, h.HandleUserInfoRequest)
	r.Post(port.RouteUserInfo, h.HandleUserInfoRequest)
}

func (h *UserInfoHandler) HandleUserInfoRequest(w http.ResponseWriter, r *http.Request) {
	tenantUUID := TenantIDFromContext(r.Context())

	// 1. Map HTTP Transport parameter blocks directly into the Port Command envelope
	cmd := port.UserInfoRequestCommand{
		TenantID:            tenantUUID,
		AuthorizationHeader: r.Header.Get("Authorization"),
		DPoPProofHeader:     r.Header.Get("DPoP"),
		HTTPMethod:          r.Method,
		RequestURL:          r.URL.String(),
	}

	// 2. Pure Delegation: Execute validations, token parsing, and claims filtering in the domain service
	claims, err := h.authUseCase.ProcessUserInfoRequest(r.Context(), cmd)
	if err != nil {
		h.writeSpecCompliantOIDCError(w, err)
		return
	}

	// 3. Success Output Generation
	w.Header().Set(model.HeaderContentType, model.ContentTypeJSON)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(claims)
}

// writeSpecCompliantOIDCError maps domain failures into RFC 6750 WWW-Authenticate header tokens automatically
func (h *UserInfoHandler) writeSpecCompliantOIDCError(w http.ResponseWriter, err error) {
	errCode := "invalid_token"
	statusCode := http.StatusUnauthorized

	if errors.Is(err, port.ErrInvalidRequest) {
		errCode = "invalid_request"
		statusCode = http.StatusBadRequest
	}

	w.Header().Set("WWW-Authenticate", `Bearer error="`+errCode+`", error_description="`+err.Error()+`"`)
	w.Header().Set(model.HeaderContentType, model.ContentTypeJSON)
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             errCode,
		"error_description": err.Error(),
	})
}
