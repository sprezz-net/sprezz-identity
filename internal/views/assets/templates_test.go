package assets

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// templateFiles returns every .templ source of the admin and public views.
func templateFiles(t *testing.T) map[string]string {
	t.Helper()
	files := map[string]string{}
	for _, dir := range []string{"../admin", "../public", "."} {
		matches, err := filepath.Glob(filepath.Join(dir, "*.templ"))
		require.NoError(t, err)
		for _, path := range matches {
			content, readErr := os.ReadFile(path)
			require.NoError(t, readErr)
			files[path] = string(content)
		}
	}
	require.NotEmpty(t, files, "no templates found; the test would pass vacuously")
	return files
}

func TestTemplates_DoNotLoadThirdPartyCode(t *testing.T) {
	banned := []string{"cdn.tailwindcss.com", "unpkg.com", "cdn.jsdelivr.net", "googleapis.com", "gstatic.com", "cdnjs."}
	for path, src := range templateFiles(t) {
		for _, host := range banned {
			assert.NotContains(t, src, host, "%s loads code from a third-party host", path)
		}
	}
}

func TestTemplates_HaveNoInlineStylesOrHandlers(t *testing.T) {
	inlineStyle := regexp.MustCompile(`\sstyle\s*=`)
	inlineHandler := regexp.MustCompile(`\son(click|load|change|input|submit|error|keydown|keyup|mouseover)\s*=`)
	styleTag := regexp.MustCompile(`<style[\s>]`)

	for path, src := range templateFiles(t) {
		assert.False(t, inlineStyle.MatchString(src), "%s uses an inline style attribute, which the CSP blocks", path)
		assert.False(t, inlineHandler.MatchString(src), "%s uses an inline event handler, which the CSP blocks", path)
		assert.False(t, styleTag.MatchString(src), "%s contains a <style> element, which the CSP blocks", path)
	}
}

func TestTemplates_ScriptTagsAreExternalAndNonced(t *testing.T) {
	scriptTag := regexp.MustCompile(`<script[^>]*>`)
	for path, src := range templateFiles(t) {
		for _, tag := range scriptTag.FindAllString(src, -1) {
			assert.Contains(t, tag, "src=", "%s has an inline script; move it into a static file: %s", path, tag)
			assert.Contains(t, tag, "nonce={ templ.GetNonce(ctx) }", "%s has a script tag without the request nonce: %s", path, tag)
		}
		assert.NotRegexp(t, regexp.MustCompile(`</script>\s*<script>`), src)
	}
}

// The CSP-friendly Alpine build cannot evaluate these constructs in attribute expressions.
func TestTemplates_AlpineExpressionsAreCSPSafe(t *testing.T) {
	attr := regexp.MustCompile(`(?:x-[a-z:.-]+|@[a-z.:-]+|:[a-z-]+)="([^"]*)"`)
	forbidden := map[string]*regexp.Regexp{
		"arrow function":      regexp.MustCompile(`=>`),
		"template literal":    regexp.MustCompile("`"),
		"global access":       regexp.MustCompile(`\b(document|window|console|Math|JSON|parseInt|parseFloat|localStorage)\b`),
		"spread":              regexp.MustCompile(`\.\.\.`),
		"property assignment": regexp.MustCompile(`\b[a-zA-Z_$]+\.[a-zA-Z_$]+\s*=[^=]`),
	}

	quoted := regexp.MustCompile(`'[^']*'`)
	for path, src := range templateFiles(t) {
		for _, m := range attr.FindAllStringSubmatch(src, -1) {
			// Text inside quotes is data, not syntax, so it is ignored.
			expression := quoted.ReplaceAllString(m[1], "''")
			for name, re := range forbidden {
				assert.False(t, re.MatchString(expression), "%s: %s in an Alpine expression: %s", path, name, m[1])
			}
		}
	}
}

// Values must reach Alpine components through data attributes, never as interpolated JavaScript, because an
// interpolated value (for example a URI containing a quote) could otherwise break out of the expression.
func TestTemplates_NoInterpolatedAlpineExpressions(t *testing.T) {
	interpolated := regexp.MustCompile(`x-data=\{\s*fmt\.Sprintf\(`)
	for path, src := range templateFiles(t) {
		assert.False(t, interpolated.MatchString(src), "%s builds an x-data expression with fmt.Sprintf; use a data-* attribute", path)
	}
}

func TestTemplates_EveryPageUsesTheSharedHead(t *testing.T) {
	for path, src := range templateFiles(t) {
		if strings.HasSuffix(path, "head.templ") {
			continue
		}
		if strings.Contains(src, "<head>") {
			assert.Regexp(t, `@assets\.(Head|Styles)\(\)`, src, "%s has a <head> without the shared asset block", path)
		}
	}
}
