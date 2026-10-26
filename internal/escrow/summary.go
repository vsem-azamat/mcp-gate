package escrow

import (
	"encoding/json"
	"strings"
	"unicode/utf8"
)

// DefaultSourceArguments are the request arguments kept in a source summary unless configured
// otherwise: the ones that identify where a secret came from in chat and mail servers (chat,
// space, message, attachment) without carrying message text or the secret itself.
var DefaultSourceArguments = []string{
	"chat_id", "message_id", "message_ids", "topic_id", "reply_to",
	"space", "space_name", "message_name", "thread_name", "attachment_name",
	"conversation_id", "conversationId", "channel_id", "chat", "peer",
	"messageId", "threadId", "account",
}

// Limits of a source summary's values.
const (
	maxSourceStringBytes = 200
	maxSourceListItems   = 20
)

// summarize keeps the members of a request's arguments that e.sources names: strings of at
// most 200 bytes without line breaks, numbers and booleans, and lists of at most 20 strings and
// numbers.
func (e *Escrow) summarize(arguments map[string]any) map[string]any {
	summary := map[string]any{}
	for key, value := range arguments {
		if !e.sources[key] {
			continue
		}
		switch v := value.(type) {
		case string:
			if len(v) <= maxSourceStringBytes && !strings.ContainsAny(v, "\r\n") {
				summary[key] = v
			}
		case float64, int, int64, bool, json.Number:
			summary[key] = v
		case []any:
			if len(v) <= maxSourceListItems {
				items := make([]any, 0, len(v))
				for _, item := range v {
					switch item.(type) {
					case string, float64, int, int64, json.Number:
						items = append(items, item)
					}
				}
				summary[key] = items
			}
		}
	}
	return summary
}

// preview shows the first 4 and last 3 characters of a value of 12 or more, the first 2 and
// last 1 of a value of 8 to 11, and nothing of a shorter one or one that is not UTF-8.
func preview(value []byte) string {
	if !utf8.Valid(value) {
		return "…"
	}
	runes := []rune(string(value))
	switch n := len(runes); {
	case n >= 12:
		return string(runes[:4]) + "…" + string(runes[n-3:])
	case n >= 8:
		return string(runes[:2]) + "…" + string(runes[n-1:])
	default:
		return "…"
	}
}
