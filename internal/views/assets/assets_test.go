package assets

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEmbeddedFilesExist(t *testing.T) {
	for _, name := range []string{"app.css", "htmx.min.js", "alpine-csp.min.js", "admin.js", "logout.js"} {
		content, err := fs.ReadFile(files, name)
		require.NoError(t, err, name)
		assert.NotEmpty(t, content, name)
	}
}

func TestURL_IsVersioned(t *testing.T) {
	url := URL("app.css")
	assert.True(t, strings.HasPrefix(url, "/assets/app.css?v="), url)
	assert.Len(t, strings.TrimPrefix(url, "/assets/app.css?v="), 12)
	assert.Equal(t, url, URL("app.css"), "the version must be stable between calls")
	assert.NotEqual(t, URL("app.css"), URL("admin.js"))
	assert.Equal(t, "/assets/unknown.js", URL("unknown.js"), "unknown files get a plain URL")
}

func TestHandler_ServesVersionedFilesWithLongCache(t *testing.T) {
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, URL("htmx.min.js"), nil))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Cache-Control"), "immutable")
	assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
	assert.Contains(t, rec.Header().Get("Content-Type"), "javascript")
	assert.NotEmpty(t, rec.Body.Bytes())
}

func TestHandler_UnversionedFilesMustRevalidate(t *testing.T) {
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/assets/app.css", nil))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "no-cache", rec.Header().Get("Cache-Control"))
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/css")
}

func TestHandler_Rejections(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
		want   int
	}{
		{name: "missing file", method: http.MethodGet, path: "/assets/nope.js", want: http.StatusNotFound},
		{name: "directory listing", method: http.MethodGet, path: "/assets/", want: http.StatusNotFound},
		{name: "path traversal", method: http.MethodGet, path: "/assets/../assets.go", want: http.StatusNotFound},
		{name: "source file is not embedded", method: http.MethodGet, path: "/assets/input.css", want: http.StatusNotFound},
		{name: "post is refused", method: http.MethodPost, path: "/assets/app.css", want: http.StatusMethodNotAllowed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			Handler().ServeHTTP(rec, httptest.NewRequest(tt.method, tt.path, nil))
			assert.Equal(t, tt.want, rec.Code)
		})
	}
}

// The admin script must stay free of constructs that the CSP-friendly Alpine build cannot evaluate.
func TestAdminScript_HasNoEval(t *testing.T) {
	for _, name := range []string{"admin.js", "logout.js"} {
		content, err := fs.ReadFile(files, name)
		require.NoError(t, err)
		for _, banned := range []string{"eval(", "new Function(", "document.write(", "innerHTML ="} {
			assert.NotContains(t, string(content), banned, "%s must not use %s", name, banned)
		}
	}
}
