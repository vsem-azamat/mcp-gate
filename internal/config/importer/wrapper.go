package importer

import (
	"path"
	"regexp"
	"strings"
)

var assignRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// envWrapper is a command line of the form `env [options] [NAME=VALUE...] command [args...]`,
// taken apart.
type envWrapper struct {
	ignoreEnv bool              // -i: the command gets only the assignments
	unset     []string          // -u NAME
	chdir     string            // -C DIR
	assign    map[string]string // NAME=VALUE before the command
	command   string
	args      []string
}

// isEnvCommand reports whether command runs env(1).
func isEnvCommand(command string) bool { return path.Base(command) == "env" }

// parseEnvWrapper takes apart the arguments of env(1). It returns false for a form it does not
// understand (an unknown option, -S, or no command), which the caller keeps as it is.
func parseEnvWrapper(args []string) (envWrapper, bool) {
	w := envWrapper{assign: map[string]string{}}
	i := 0
	needValue := func() (string, bool) {
		if i+1 >= len(args) {
			return "", false
		}
		i++
		return args[i], true
	}
options:
	for ; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			i++
			break options
		case a == "-i" || a == "--ignore-environment" || a == "-":
			w.ignoreEnv = true
		case a == "-u" || a == "--unset":
			v, ok := needValue()
			if !ok {
				return w, false
			}
			w.unset = append(w.unset, v)
		case strings.HasPrefix(a, "--unset="):
			w.unset = append(w.unset, strings.TrimPrefix(a, "--unset="))
		case strings.HasPrefix(a, "-u") && len(a) > 2:
			w.unset = append(w.unset, a[2:])
		case a == "-C" || a == "--chdir":
			v, ok := needValue()
			if !ok {
				return w, false
			}
			w.chdir = v
		case strings.HasPrefix(a, "--chdir="):
			w.chdir = strings.TrimPrefix(a, "--chdir=")
		case strings.HasPrefix(a, "-C") && len(a) > 2:
			w.chdir = a[2:]
		case strings.HasPrefix(a, "-"):
			return w, false
		default:
			break options
		}
	}
	for ; i < len(args) && assignRE.MatchString(args[i]); i++ {
		name, value, _ := strings.Cut(args[i], "=")
		w.assign[name] = value
	}
	if i >= len(args) {
		return w, false
	}
	w.command = args[i]
	w.args = append([]string(nil), args[i+1:]...)
	return w, true
}
