package assets

import (
	"io/fs"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The admin handlers read the typed delete confirmation from the request body (see parseBodyForm). htmx 1.x sends
// DELETE parameters in the body, while htmx 2.x moves them to the URL. This test fails loudly on such an upgrade,
// so the confirmation can never silently arrive empty.
func TestHtmx_DeleteParametersTravelInTheBody(t *testing.T) {
	content, err := fs.ReadFile(files, "htmx.min.js")
	require.NoError(t, err)
	src := string(content)

	assert.Contains(t, src, `methodsThatUseUrlParams:["get"]`,
		"htmx must keep sending DELETE form data in the body; update parseBodyForm before upgrading")
	assert.Contains(t, src, `version:"1.9.`, "htmx was upgraded; re-verify the delete confirmation flow")
}

// The hardened configuration must stay in the shared head so eval and inline style injection stay off.
func TestHtmx_ConfigStaysHardened(t *testing.T) {
	for _, setting := range []string{`"allowEval":false`, `"allowScriptTags":false`, `"includeIndicatorStyles":false`, `"selfRequestsOnly":true`} {
		assert.Contains(t, htmxConfig, setting)
	}
}
