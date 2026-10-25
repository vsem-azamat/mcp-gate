package downstream

import (
	"bufio"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

func TestFrameID(t *testing.T) {
	t.Parallel()
	big := strings.Repeat("x", 5000)
	cases := []struct {
		frame string
		want  any // nil: no id found
	}{
		{`{"jsonrpc":"2.0","id":7,"result":{"text":"` + big + `"}}`, float64(7)},
		{`{"id":"abc","jsonrpc":"2.0","result":"` + big + `"}`, "abc"},
		{`{"result":{"text":"` + big + `"},"jsonrpc":"2.0","id":12}` + "\n", float64(12)}, // TypeScript SDK order
		{`{"result":"` + big + `","id":3,"jsonrpc":"2.0"}`, float64(3)},
		{`{"jsonrpc":"2.0","method":"notifications/message","params":{"data":"` + big + `"}}`, nil},
		{`{"jsonrpc":"2.0","result":{"x":"` + big + `","nested":{"id":5}}}`, nil},
		{`{"jsonrpc":"2.0","id":7,"method":"sampling/createMessage","params":{"m":"` + big + `"}}`, nil}, // a request from the server
		{`{"params":{"m":"` + big + `"},"method":"roots/list","jsonrpc":"2.0","id":7}`, nil},
	}
	for _, tc := range cases {
		br := bufio.NewReaderSize(strings.NewReader(tc.frame), 16)
		line, f, err := readFrame(br, 1024)
		if line != nil || f == nil || (err != nil && !errors.Is(err, io.EOF)) {
			t.Fatalf("readFrame = %q, %+v, %v", line, f, err)
		}
		if f.size != len(tc.frame) {
			t.Errorf("size = %d, want %d", f.size, len(tc.frame))
		}
		id, ok := frameID(f)
		if tc.want == nil {
			if ok {
				t.Errorf("frameID found %v in %.60s", id.Raw(), tc.frame)
			}
			continue
		}
		if want, _ := jsonrpc.MakeID(tc.want); !ok || id != want {
			t.Errorf("frameID = %v, %v; want %v", id.Raw(), ok, tc.want)
		}
	}
}

func TestReadFrameUnderLimit(t *testing.T) {
	t.Parallel()
	br := bufio.NewReaderSize(strings.NewReader(strings.Repeat("a", 100)+"\nnext\n"), 16)
	line, f, err := readFrame(br, 101)
	if f != nil || err != nil || len(line) != 101 {
		t.Fatalf("readFrame = %d bytes, %v, %v", len(line), f, err)
	}
	if line, _, _ := readFrame(br, 101); string(line) != "next\n" {
		t.Errorf("next frame = %q", line)
	}
}

func TestEventLimiter(t *testing.T) {
	t.Parallel()
	id, _ := jsonrpc.MakeID(float64(4))
	big := strings.Repeat("y", 2000)
	stream := "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"m\":\"" + big + "\"}}\n\n" +
		"event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n" +
		"id: 9\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":4,\"result\":{\"t\":\"" + big + "\"}}\n\n"
	l := &eventLimiter{
		src: io.NopCloser(strings.NewReader(stream)), limit: 1024, id: id, isCall: true,
		logger: slog.New(slog.DiscardHandler), lineStart: true,
	}
	l.br = bufio.NewReaderSize(l.src, 64)
	out, err := io.ReadAll(l)
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	want := "\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n" +
		"event: message\ndata: " + string(oversizedResponse(id, 1024)) + "\n\n"
	if got != want {
		t.Errorf("stream =\n%q\nwant\n%q", got, want)
	}
}
