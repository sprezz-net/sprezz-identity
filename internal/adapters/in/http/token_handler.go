package http

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"sprezz-identity/internal/domain/model"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func (h *HttpAdapter) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request, tenant *model.Tenant) {
	clientID := r.FormValue("client_id")
	code := r.FormValue("code")
	codeVerifier := r.FormValue("code_verifier")
	if clientID == "" || code == "" || codeVerifier == "" {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "client_id, code and code_verifier are required"})
		return
	}
	dpopJKT, err := h.validateDPoPProof(r)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": errInvalidDPoP + err.Error()})
		return
	}
	tokens, err := h.authPort.ExchangeCodeForTokens(r.Context(), tenant.ID, clientID, code, codeVerifier, dpopJKT)
	if err != nil {
		respondJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}
	respondJSON(w, http.StatusOK, tokens)
}

func (h *HttpAdapter) authenticateClient(w http.ResponseWriter, r *http.Request, tenant *model.Tenant) (*model.ClientApplication, error) {
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	if clientID == "" || clientSecret == "" {
		respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "client_id and client_secret are required"})
		return nil, fmt.Errorf("client_id and client_secret are required")
	}

	client, err := h.storagePort.GetClient(r.Context(), tenant.ID, clientID)
	if err != nil {
		respondJSON(w, http.StatusUnauthorized, map[string]string{"error": errClientAuthFailed})
		return nil, fmt.Errorf("%s", errClientAuthFailed)
	}

	if client.ClientType == model.ClientTypeInternalEphemeral {
		if h.adminState == nil || h.adminState.GetEphemeralSecret() != clientSecret {
			respondJSON(w, http.StatusUnauthorized, map[string]string{"error": errClientAuthFailed})
			return nil, fmt.Errorf("%s", errClientAuthFailed)
		}
		return client, nil
	}

	if client.ClientSecret == nil || *client.ClientSecret != clientSecret {
		respondJSON(w, http.StatusUnauthorized, map[string]string{"error": errClientAuthFailed})
		return nil, fmt.Errorf("%s", errClientAuthFailed)
	}

	return client, nil
}

func (h *HttpAdapter) handleClientCredentialsGrant(w http.ResponseWriter, r *http.Request, tenant *model.Tenant) {
	client, err := h.authenticateClient(w, r, tenant)
	if err != nil {
		return
	}
	dpopJKT, err := h.validateDPoPProof(r)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": errInvalidDPoP + err.Error()})
		return
	}
	issuedAt := time.Now().UTC()
	accessToken, err := h.cryptoPort.SignAccessToken(model.TokenClaims{
		TokenID:   uuid.NewString(),
		Issuer:    schemeHttps + tenant.Domain,
		TenantID:  tenant.ID.String(),
		Subject:   client.ClientID,
		ClientID:  client.ClientID,
		Scopes:    client.DefaultScopes,
		IssuedAt:  issuedAt,
		ExpiresAt: issuedAt.Add(client.AccessTokenLifetime),
		Audiences: client.AllowedAudiences,
		DPoPHash:  dpopJKT,
	}, client.Algorithm)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	tokenType := "Bearer"
	if dpopJKT != "" {
		tokenType = "DPoP"
	}
	respondJSON(w, http.StatusOK, &model.TokenSetResponse{
		AccessToken: accessToken,
		TokenType:   tokenType,
		ExpiresIn:   int64(client.AccessTokenLifetime / time.Second),
	})
}

func (h *HttpAdapter) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed token request"})
		return
	}
	grantType := r.FormValue("grant_type")
	tenant, ok := TenantFromContext(r.Context())
	if !ok {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": errTenantNotResolved})
		return
	}

	switch grantType {
	case "authorization_code":
		h.handleAuthorizationCodeGrant(w, r, tenant)
	case "client_credentials":
		h.handleClientCredentialsGrant(w, r, tenant)
	default:
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported grant_type"})
	}
}

func (h *HttpAdapter) validateUserInfoDPoP(r *http.Request, claims jwt.MapClaims, isDPoP bool) error {
	cnfVal, ok := claims["cnf"].(map[string]any)
	if !ok {
		return nil
	}
	jktVal, _ := cnfVal["jkt"].(string)
	if jktVal == "" {
		return nil
	}
	if !isDPoP {
		return errors.New("token is DPoP-bound, but Bearer scheme was used")
	}
	dpopJKT, err := h.validateDPoPProof(r)
	if err != nil {
		return fmt.Errorf("%s%w", errInvalidDPoP, err)
	}
	if dpopJKT != jktVal {
		return errors.New("DPoP proof key mismatch")
	}
	return nil
}

func (h *HttpAdapter) parseDPoPPubKey(dpopHeader string) (*rsa.PublicKey, string, error) {
	parser := new(jwt.Parser)
	token, _, err := parser.ParseUnverified(dpopHeader, jwt.MapClaims{})
	if err != nil {
		return nil, "", fmt.Errorf("invalid DPoP header format: %w", err)
	}

	jwkHeader, ok := token.Header["jwk"].(map[string]any)
	if !ok || jwkHeader == nil {
		return nil, "", errors.New("missing jwk in DPoP header")
	}

	typHeader, _ := token.Header["typ"].(string)
	if typHeader != "dpop+jwt" {
		return nil, "", errors.New("invalid DPoP header typ, must be dpop+jwt")
	}

	jwkJSON, err := json.Marshal(jwkHeader)
	if err != nil {
		return nil, "", fmt.Errorf("marshal jwk: %w", err)
	}

	var rsaPub struct {
		Kty string `json:"kty"`
		N   string `json:"n"`
		E   string `json:"e"`
	}
	if err := json.Unmarshal(jwkJSON, &rsaPub); err != nil {
		return nil, "", fmt.Errorf("unmarshal rsa jwk: %w", err)
	}
	if rsaPub.Kty != "RSA" {
		return nil, "", fmt.Errorf("unsupported JWK kty: %s", rsaPub.Kty)
	}

	nBytes, err := base64.RawURLEncoding.DecodeString(rsaPub.N)
	if err != nil {
		return nil, "", fmt.Errorf("decode jwk n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(rsaPub.E)
	if err != nil {
		return nil, "", fmt.Errorf("decode jwk e: %w", err)
	}
	if len(eBytes) < 1 {
		return nil, "", errors.New("invalid jwk e")
	}
	var eVal int
	for _, b := range eBytes {
		eVal = (eVal << 8) | int(b)
	}

	pubKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: eVal,
	}

	sortedJWKJSON := fmt.Sprintf(`{"e":"%s","kty":"RSA","n":"%s"}`, rsaPub.E, rsaPub.N)
	hsh := sha256.Sum256([]byte(sortedJWKJSON))
	jkt := base64.RawURLEncoding.EncodeToString(hsh[:])

	return pubKey, jkt, nil
}

func (h *HttpAdapter) validateDPoPClaims(r *http.Request, claims jwt.MapClaims) (time.Time, error) {
	htm, _ := claims["htm"].(string)
	htu, _ := claims["htu"].(string)
	jti, _ := claims["jti"].(string)
	iatVal, _ := claims["iat"].(float64)

	if htm == "" || htu == "" || jti == "" || iatVal == 0 {
		return time.Time{}, errors.New("missing mandatory DPoP claims (htm, htu, jti, iat)")
	}

	if !strings.EqualFold(htm, r.Method) {
		return time.Time{}, fmt.Errorf("DPoP htm mismatch: expected %s, got %s", r.Method, htm)
	}

	reqURL := schemeHttps + r.Host + r.URL.Path
	if !strings.HasPrefix(htu, "http://") && !strings.HasPrefix(htu, "https://") {
		reqURL = r.URL.Path
	}
	normHTU := strings.Split(htu, "?")[0]
	normReq := strings.Split(reqURL, "?")[0]
	if !strings.HasSuffix(normReq, normHTU) && !strings.HasSuffix(normHTU, normReq) {
		return time.Time{}, fmt.Errorf("DPoP htu mismatch: expected %s, got %s", normReq, normHTU)
	}

	iat := time.Unix(int64(iatVal), 0)
	now := time.Now()
	if iat.Before(now.Add(-2*time.Minute)) || iat.After(now.Add(2*time.Minute)) {
		return time.Time{}, errors.New("DPoP proof has expired or is in the future")
	}

	return iat, nil
}

func (h *HttpAdapter) validateDPoPProof(r *http.Request) (string, error) {
	dpopHeader := r.Header.Get("DPoP")
	if dpopHeader == "" {
		return "", nil
	}

	pubKey, jkt, err := h.parseDPoPPubKey(dpopHeader)
	if err != nil {
		return "", err
	}

	parsedToken, err := jwt.Parse(dpopHeader, func(t *jwt.Token) (any, error) {
		return pubKey, nil
	})
	if err != nil || !parsedToken.Valid {
		return "", fmt.Errorf("invalid DPoP proof signature: %w", err)
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("invalid DPoP claims")
	}

	iat, err := h.validateDPoPClaims(r, claims)
	if err != nil {
		return "", err
	}

	jti, _ := claims["jti"].(string)
	used, err := h.storagePort.IsDPoPProofUsed(r.Context(), jti)
	if err != nil || used {
		return "", errors.New("DPoP proof jti has already been used")
	}

	if err := h.storagePort.SaveDPoPProof(r.Context(), jti, iat.Add(5*time.Minute)); err != nil {
		return "", fmt.Errorf("save DPoP proof: %w", err)
	}

	return jkt, nil
}
