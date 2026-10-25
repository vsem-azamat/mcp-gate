package escrow

import (
	"encoding/json"
	"strings"
	"unicode/utf8"
)

// summaryKeys are the request arguments that identify where a secret came from (chat, space,
// message, attachment) without carrying message text or the secret itself.
var summaryKeys = map[string]bool{
	"chat_id": true, "message_id": true, "message_ids": true, "topic_id": true, "reply_to": true,
	"space": true, "space_name": true, "message_name": true, "thread_name": true, "attachment_name": true,
	"conversation_id": true, "conversationId": true, "channel_id": true, "chat": true, "peer": true,
	"messageId": true, "threadId": true, "account": true,
}

// Summarize keeps the identifying members of a request's arguments: strings of at most 200
// bytes without line breaks, numbers and booleans, and lists of at most 20 strings and numbers.
func Summarize(arguments map[string]any) map[string]any {
	summary := map[string]any{}
	for key, value := range arguments {
		if !summaryKeys[key] {
			continue
		}
		switch v := value.(type) {
		case string:
			if len(v) <= 200 && !strings.ContainsAny(v, "\r\n") {
				summary[key] = v
			}
		case float64, int, int64, bool, json.Number:
			summary[key] = v
		case []any:
			if len(v) <= 20 {
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
