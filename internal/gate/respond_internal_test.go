package gate

import "testing"

func TestClassify(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name, body string
		want       bodyKind
	}{
		{"call", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"x"}}}`, bodyPlain},
		{"leading space", " \n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}", bodyPlain},
		{"notification", `{"jsonrpc":"2.0","method":"notifications/initialized"}`, bodyPlain},
		{"progress token", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"p","_meta":{"progressToken":"t"}}}`, bodyStream},
		{"numeric progress token", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"_meta":{"progressToken":3}}}`, bodyStream},
		{"escaped progress token", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"_meta":{"progress\u0054oken":"t"}}}`, bodyStream},
		{"other case", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"_META":{"progressToken":"t"}}}`, bodyPlain},
		{"other case of params", `{"jsonrpc":"2.0","id":1,"method":"tools/call","PARAMS":{"_meta":null},"params":{"_meta":{"progressToken":1}}}`, bodyStream},
		{"progress token in arguments", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"progressToken"}}}`, bodyPlain},
		{"escape in arguments", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"caf\u00e9"}}}`, bodyPlain},
		{"listen", `{"jsonrpc":"2.0","id":1,"method":"subscriptions/listen","params":{}}`, bodyListen},
		{"escaped listen", `{"jsonrpc":"2.0","id":1,"method":"subscriptions\u002flisten"}`, bodyListen},
		{"listen with an escaped slash", `{"jsonrpc":"2.0","id":1,"method":"subscriptions\/listen"}`, bodyListen},
		{"listen and another case", `{"jsonrpc":"2.0","id":1,"method":"subscriptions/listen","METHOD":"x"}`, bodyListen},
		{"listen in arguments", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{"text":"subscriptions/listen"}}}`, bodyPlain},
		{"batch", `[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]`, bodyStream},
		{"params not an object", `{"jsonrpc":"2.0","id":1,"method":"x","params":["progressToken"]}`, bodyStream},
		{"malformed with a token", `{"progressToken"`, bodyStream},
		{"empty", ``, bodyStream},
	} {
		if got := classify([]byte(c.body)); got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}
}

func TestAccepts(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		values       []string
		json, stream bool
	}{
		{[]string{"application/json, text/event-stream"}, true, true},
		{[]string{"application/json", "text/event-stream"}, true, true},
		{[]string{"Application/JSON;q=0.9"}, true, false},
		{[]string{" text/event-stream "}, false, true},
		{[]string{"*/*"}, true, true},
		{[]string{"application/*, text/*"}, true, true},
		{[]string{"text/html"}, false, false},
		{[]string{"application/json;q=0, text/event-stream"}, false, true},
		{[]string{"application/json; Q=0.0"}, false, false},
		{[]string{"application/json;q=0.1"}, true, false},
		{[]string{"application/json;q=0, */*"}, false, true},
		{[]string{"*/*;q=0"}, false, false},
		{[]string{"*/*;q=0, text/event-stream"}, false, true},
		{nil, false, false},
	} {
		if j, s := accepts(c.values); j != c.json || s != c.stream {
			t.Errorf("%q: %v %v, want %v %v", c.values, j, s, c.json, c.stream)
		}
	}
}
