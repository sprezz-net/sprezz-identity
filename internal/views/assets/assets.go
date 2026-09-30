// Package assets embeds the static files of the web UI (compiled stylesheet, htmx, Alpine.js and the admin
// script) and serves them from the binary, so pages never load code from a third-party origin.
package assets

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
	"net/http"
	"strings"
)

// Prefix is the URL path under which the embedded files are served.
const Prefix = "/assets/"

//go:embed static
var embedded embed.FS

var (
	files    fs.FS
	versions = map[string]string{}
)

func init() {
	sub, err := fs.Sub(embedded, "static")
	if err != nil {
		panic("assets: embedded static directory is missing: " + err.Error())
	}
	files = sub

	// A short content hash makes every URL change when the file changes, which allows long-lived caching.
	_ = fs.WalkDir(files, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		content, readErr := fs.ReadFile(files, path)
		if readErr != nil {
			return readErr
		}
		sum := sha256.Sum256(content)
		versions[path] = hex.EncodeToString(sum[:])[:12]
		return nil
	})
}

// URL returns the cache-busting URL of an embedded file, for example "/assets/app.css?v=1a2b3c4d5e6f".
func URL(name string) string {
	if v, ok := versions[name]; ok {
		return Prefix + name + "?v=" + v
	}
	return Prefix + name
}

// Handler serves the embedded files. Versioned requests are cached for a year, others must revalidate.
func Handler() http.Handler {
	fileServer := http.StripPrefix(Prefix, http.FileServer(http.FS(files)))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// Directory listings are never exposed.
		if strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.URL.Query().Get("v") != "" {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		fileServer.ServeHTTP(w, r)
	})
}
