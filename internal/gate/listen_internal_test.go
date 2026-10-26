package gate

import "testing"

func TestLoopbackListen(t *testing.T) {
	for _, tc := range []struct {
		addr string
		want bool
	}{{"127.0.0.1:8790", true}, {"[::1]:8790", true}, {"localhost:8790", true}, {"0.0.0.0:8790", false}, {"192.0.2.1:8790", false}, {":8790", false}} {
		if got := loopbackListen(tc.addr); got != tc.want {
			t.Errorf("loopbackListen(%q) = %v, want %v", tc.addr, got, tc.want)
		}
	}
}
