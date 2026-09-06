package model

// TokenType defines a spec-compliant string token indicator profile (RFC 8693) [3.1].
type TokenType string

const (
	// Upstream/External Assertions
	TokenTypeIDToken     TokenType = "urn:ietf:params:oauth:token-type:id_token"
	TokenTypeAccessToken TokenType = "urn:ietf:params:oauth:token-type:access_token"

	// Legacy/Specialized Hint Profile Assertions
	TokenTypeRefreshToken TokenType = "urn:ietf:params:oauth:token-type:refresh_token"
	TokenTypeJWT          TokenType = "urn:ietf:params:oauth:token-type:jwt"
	TokenTypeSaml2        TokenType = "urn:ietf:params:oauth:token-type:saml2"
)

const (
	AdminUIProfileName        = "sprezz_admin_ui_profile"
	AdminUIGroupName          = "sprezz_admin_ui_group"
	ContentTypeFormUrlEncoded = "application/x-www-form-urlencoded"
	ContentTypeJSON           = "application/json; charset=utf-8"
	ContentTypeHTML           = "text/html; charset=utf-8"
	ContentTypePlainText      = "text/plain; charset=utf-8"
	CookieSessionNameProd     = "__Host-spz_session"
	CookieSessionNameDev      = "spz_session"
	HeaderContentType         = "Content-Type"
	HeaderXForwardedProto     = "X-Forwarded-Proto"
	HeaderHXRedirect          = "HX-Redirect"
	HeaderHXRequest           = "HX-Request"
	SchemeHttp                = "http"
	SchemeHttps               = "https"
)
