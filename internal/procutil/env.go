// Package procutil starts and stops child processes: a clean environment, a process group of
// their own that is signalled as a whole, a raised OOM score, line-by-line logging of stderr,
// and, for the gate itself, non-dumpable memory and reaping of orphaned grandchildren.
//
// It is written for Linux. On other Unix systems the process group handling works, and the OOM
// score, the dumpable flag and the subreaper are no-ops.
package procutil

import (
	"sort"
	"strings"
)

// Environ builds a child's environment: the variables of parent (in os.Environ form) that
// inherit names, then explicit, which wins over inherited values. An inherit entry ending in *
// matches every name with that prefix. The result is sorted by name.
func Environ(parent, inherit []string, explicit map[string]string) []string {
	vars := map[string]string{}
	for _, kv := range parent {
		name, value, ok := strings.Cut(kv, "=")
		if !ok || name == "" {
			continue
		}
		if inherited(name, inherit) {
			vars[name] = value
		}
	}
	for name, value := range explicit {
		vars[name] = value
	}
	out := make([]string, 0, len(vars))
	for name, value := range vars {
		out = append(out, name+"="+value)
	}
	sort.Strings(out)
	return out
}

func inherited(name string, inherit []string) bool {
	for _, pattern := range inherit {
		if prefix, ok := strings.CutSuffix(pattern, "*"); ok {
			if strings.HasPrefix(name, prefix) {
				return true
			}
		} else if name == pattern {
			return true
		}
	}
	return false
}
