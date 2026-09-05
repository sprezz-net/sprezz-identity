package http

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"sprezz-identity/internal/domain/model"
	"sprezz-identity/internal/domain/port"

	"github.com/google/uuid"
)

// authenticateClientContext extracts, parses, and strictly validates client credentials
// against registered profile methods to prevent downgrades across back-channel HTTP endpoints.
func authenticateClientContext(r *http.Request, tenantID uuid.UUID, storage port.Storage, crypto port.Crypto) (string, string, bool, *model.Application, *model.ApplicationProfile, *model.ApplicationGroup, error) {
	var clientID, clientSecret string
	detectedMethod := model.AuthMethodNone

	// Track 1: Detect and parse standard HTTP Basic Authentication Headers
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Basic ") {
		payload, err := base64.StdEncoding.DecodeString(authHeader[6:])
		if err == nil {
			pair := strings.SplitN(string(payload), ":", 2)
			if len(pair) == 2 {
				clientID = pair[0]
				clientSecret = pair[1]
				detectedMethod = model.AuthMethodClientSecretBasic
			}
		}
	}

	// Track 2: If basic auth header is absent, check inline form fields
	if detectedMethod == model.AuthMethodNone {
		clientID = r.Form.Get("client_id")
		clientSecret = r.Form.Get("client_secret")
		if clientSecret != "" {
			detectedMethod = model.AuthMethodClientSecretPost
		}
	}

	if clientID == "" {
		clientID = r.Form.Get("client_id")
	}

	if clientID == "" {
		return "", "", false, nil, nil, nil, errors.New("missing client identifier")
	}

	app, profile, group, err := storage.GetApplicationByClientID(r.Context(), tenantID, clientID)
	if err != nil {
		return "", "", false, nil, nil, nil, err
	}

	// Spec Enforcement: Confirm the detected transport method matches the application profile exactly
	if profile.TokenEndpointAuthMethod != detectedMethod {
		return clientID, "", false, nil, nil, nil, port.ErrInvalidClient
	}

	if profile.TokenEndpointAuthMethod == model.AuthMethodNone {
		return clientID, "", true, app, profile, group, nil
	}

	if app.ClientSecretHash == nil || clientSecret == "" {
		return clientID, "", false, nil, nil, nil, port.ErrInvalidClient
	}

	authenticated, err := crypto.CompareCredential(*app.ClientSecretHash, clientSecret)
	if err != nil || !authenticated {
		return clientID, "", false, nil, nil, nil, port.ErrInvalidClient
	}

	return clientID, clientSecret, true, app, profile, group, nil
}
