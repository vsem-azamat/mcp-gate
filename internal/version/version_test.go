package version

import (
	"runtime/debug"
	"testing"
)

func TestFrom(t *testing.T) {
	t.Parallel()
	settings := func(rev, modified string) []debug.BuildSetting {
		return []debug.BuildSetting{{Key: "vcs.revision", Value: rev}, {Key: "vcs.modified", Value: modified}}
	}
	const rev = "3bc332799d4c0ad4f958483fc6541f2066bc87ad"
	tests := []struct {
		name  string
		given string
		bi    *debug.BuildInfo
		want  string
	}{
		{"checkout", "", &debug.BuildInfo{Settings: settings(rev, "false")}, "dev (3bc332799d4c)"},
		{"release", "v0.4.0", &debug.BuildInfo{Settings: settings(rev, "false")}, "v0.4.0 (3bc332799d4c)"},
		{"changes", "", &debug.BuildInfo{Settings: settings(rev, "true")}, "dev (3bc332799d4c-dirty)"},
		{"short revision", "", &debug.BuildInfo{Settings: settings("abc", "false")}, "dev (abc)"},
		{"no revision", "", &debug.BuildInfo{}, "dev (unknown)"},
		{"no build info", "", nil, "dev (unknown)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := from(tt.given, tt.bi).String(); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
