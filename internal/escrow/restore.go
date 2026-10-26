package escrow

import (
	"regexp"

	"github.com/vsem-azamat/mcp-gate/internal/redact"
)

// restorable matches what Restore replaces: the marker of a kept value, with its handle in
// group 1, or the continuation marker of a token split across two JSON strings.
var restorable = regexp.MustCompile(`\[REDACTED:[a-z_]+ #(k[a-z2-7]{10})\]|` + regexp.QuoteMeta(redact.ContinuationMarker))

// Restore returns text with each marker of a kept value replaced by its value, as value returns
// it for the handle, and each continuation marker removed: the value kept for the first part of
// a split token is the whole token, so the token is restored in full where it started. A marker
// whose handle value does not know is left as it is. It is how a consumer of the API puts the
// released secrets back into a redacted text.
func Restore(text string, value func(handle string) (string, bool)) string {
	return restorable.ReplaceAllStringFunc(text, func(m string) string {
		if m == redact.ContinuationMarker {
			return ""
		}
		if v, ok := value(restorable.FindStringSubmatch(m)[1]); ok {
			return v
		}
		return m
	})
}
