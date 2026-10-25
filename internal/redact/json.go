package redact

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"strings"
)

// maxJSONDepth bounds how far JSON nested inside JSON strings is followed.
const maxJSONDepth = 5

// minSecretNumberLength is the length a number under a secret member needs to be replaced; a
// shorter one ("pin": 1) is a flag or a count.
const minSecretNumberLength = 3

// nestedSafeKeys are members inside a secret object that describe the secret rather than hold
// it ({"token": {"type": "Bearer", "expires_in": 3600}}).
var nestedSafeKeys = []string{
	"user", "username", "login", "email", "type", "tokentype", "scope", "scopes",
	"expires", "expiresin", "expiresat", "expiry", "issuer", "name", "id", "kind",
}

func looksLikeJSON(text string) bool {
	trimmed := strings.TrimSpace(text)
	if len(trimmed) < 2 {
		return false
	}
	first, last := trimmed[0], trimmed[len(trimmed)-1]
	return ((first == '{' && last == '}') || (first == '[' && last == ']')) && json.Valid([]byte(trimmed))
}

// redactJSONValue redacts one decoded JSON string value. secretKind is set when the value sits
// under a secret member (directly or nested): it is then replaced as a whole or, when it is
// itself JSON, rewritten with everything inside treated as secret.
func (e *Engine) redactJSONValue(secretKind, value string, r Replacer, depth int) string {
	if secretKind != "" && !e.disabled[secretKind] {
		if depth < maxJSONDepth && looksLikeJSON(value) {
			if out, err := e.rewriteJSON([]byte(value), r, depth+1, secretKind); err == nil {
				return string(out)
			}
		}
		if !isPlaceholderValue(value) {
			return r.Replace(Finding{Kind: secretKind, Value: value})
		}
		return value
	}
	return e.redactString(value, r, depth)
}

// errBadString reports a string literal that does not decode; it cannot happen for valid JSON.
var errBadString = errors.New("redact: undecodable JSON string")

// rewriteJSON rewrites the string values of data, which is valid JSON. inherited is the secret
// kind of the member the whole document sits under, or "" at the top level.
func (e *Engine) rewriteJSON(data []byte, r Replacer, depth int, inherited string) ([]byte, error) {
	type frame struct {
		object    bool
		expectKey bool
		key       string
		// inherited is the secret kind of an enclosing secret member: every value below it is
		// secret unless its own name says otherwise.
		inherited string
	}
	stack := make([]frame, 0, 8)
	currentKey := func() string {
		if len(stack) == 0 {
			return ""
		}
		return stack[len(stack)-1].key
	}
	// secretKind is the kind of the value at the current position, or "".
	secretKind := func() string {
		if len(stack) == 0 {
			return inherited
		}
		top := stack[len(stack)-1]
		if kind, ok := secretKeyKind(top.key); ok {
			return kind
		}
		if top.inherited != "" && !slices.Contains(nestedSafeKeys, normalizeKey(top.key)) {
			return top.inherited
		}
		return ""
	}
	var out bytes.Buffer
	last := 0
	for i := 0; i < len(data); {
		switch data[i] {
		case '{':
			stack = append(stack, frame{object: true, expectKey: true, inherited: secretKind()})
			i++
		case '[':
			// Elements of an array inherit the member name it is stored under.
			stack = append(stack, frame{key: currentKey(), inherited: secretKind()})
			i++
		case '}', ']':
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			i++
		case ',':
			if len(stack) > 0 && stack[len(stack)-1].object {
				stack[len(stack)-1].expectKey = true
			}
			i++
		case ':':
			if len(stack) > 0 {
				stack[len(stack)-1].expectKey = false
			}
			i++
		case '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			// A number under a secret member (a numeric PIN or password) is replaced by the
			// replacement string; the member's type changes, but the value does not leak.
			end := i + 1
			for end < len(data) && strings.IndexByte("0123456789+-.eE", data[end]) >= 0 {
				end++
			}
			if kind := secretKind(); kind != "" && !e.disabled[kind] && end-i >= minSecretNumberLength {
				out.Write(data[last:i])
				out.Write(encodeJSONString(r.Replace(Finding{Kind: kind, Value: string(data[i:end])})))
				last = end
			}
			i = end
		case '"':
			end := jsonStringEnd(data, i)
			literal := data[i:end]
			decoded, err := decodeJSONString(literal)
			if err != nil {
				return nil, errBadString
			}
			if len(stack) > 0 && stack[len(stack)-1].object && stack[len(stack)-1].expectKey {
				stack[len(stack)-1].key = decoded
			} else if redacted := e.redactJSONValue(secretKind(), decoded, r, depth); redacted != decoded {
				out.Write(data[last:i])
				out.Write(encodeJSONString(redacted))
				last = end
			}
			i = end
		default:
			i++
		}
	}
	if last == 0 {
		return data, nil
	}
	out.Write(data[last:])
	return out.Bytes(), nil
}

// jsonStringEnd returns the index just past the closing quote of the string literal starting at
// data[start]. data is valid JSON.
func jsonStringEnd(data []byte, start int) int {
	for i := start + 1; i < len(data); i++ {
		switch data[i] {
		case '\\':
			i++
		case '"':
			return i + 1
		}
	}
	return len(data)
}

func decodeJSONString(literal []byte) (string, error) {
	if !bytes.ContainsRune(literal, '\\') {
		return string(literal[1 : len(literal)-1]), nil
	}
	var s string
	err := json.Unmarshal(literal, &s)
	return s, err
}

func encodeJSONString(s string) []byte {
	var b bytes.Buffer
	encoder := json.NewEncoder(&b)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(s); err != nil {
		panic(err) // a string always encodes
	}
	return bytes.TrimRight(b.Bytes(), "\n")
}
