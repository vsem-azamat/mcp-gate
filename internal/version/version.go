// Package version says which build of mcp-gate runs: the release version and the commit.
package version

import "runtime/debug"

// Version is the release version, set at build time with
// -ldflags "-X github.com/vsem-azamat/mcp-gate/internal/version.Version=v1.2.3".
var Version string

const (
	// Dev is the version of a build that was given none, such as one built from a checkout.
	Dev = "dev"
	// Unknown is the commit of a build the toolchain recorded no revision for.
	Unknown = "unknown"
	// commitLen is how many characters of the revision name the commit.
	commitLen = 12
)

// Info is a build's version and commit.
type Info struct {
	Version string
	Commit  string // a short revision, with "-dirty" for a tree with changes, or Unknown
}

// String is "<version> (<commit>)".
func (i Info) String() string { return i.Version + " (" + i.Commit + ")" }

// Get returns the running binary's version and commit.
func Get() Info {
	bi, _ := debug.ReadBuildInfo() // nil when the binary has none
	return from(Version, bi)
}

// from combines the version given at build time with the revision the toolchain recorded.
func from(given string, bi *debug.BuildInfo) Info {
	i := Info{Version: given, Commit: Unknown}
	if i.Version == "" {
		i.Version = Dev
	}
	if bi == nil {
		return i
	}
	dirty := false
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			if s.Value != "" {
				i.Commit = s.Value[:min(len(s.Value), commitLen)]
			}
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if dirty && i.Commit != Unknown {
		i.Commit += "-dirty"
	}
	return i
}
