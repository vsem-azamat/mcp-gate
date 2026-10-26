package config

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
)

var varNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Expand replaces ${VAR} in s with the variable's value and $$ with $. Any other $ is kept. An
// unset or empty variable, an unterminated ${ and an invalid name are errors; they name the
// variable but never a value.
func Expand(s string, lookup LookupFunc) (string, error) {
	if !strings.Contains(s, "$") {
		return s, nil
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '$' || i+1 == len(s) {
			b.WriteByte(s[i])
			continue
		}
		switch s[i+1] {
		case '$':
			b.WriteByte('$')
			i++
		case '{':
			end := strings.IndexByte(s[i+2:], '}')
			if end < 0 {
				return "", errors.New("unterminated ${")
			}
			name := s[i+2 : i+2+end]
			if !varNameRE.MatchString(name) {
				return "", errors.New("invalid variable name in ${…}; write $$ for a literal $")
			}
			v, ok := lookup(name)
			if !ok || v == "" {
				return "", fmt.Errorf("environment variable %s is unset or empty", name)
			}
			b.WriteString(v)
			i += 2 + end
		default:
			b.WriteByte('$')
		}
	}
	return b.String(), nil
}

// varNames returns the names of the variables ${NAME} in s refers to, in order, as Expand reads
// them ($$ is a literal $).
func varNames(s string) []string {
	var names []string
	for i := 0; i+1 < len(s); i++ {
		if s[i] != '$' {
			continue
		}
		switch s[i+1] {
		case '$':
			i++
		case '{':
			end := strings.IndexByte(s[i+2:], '}')
			if end < 0 {
				return names
			}
			if name := s[i+2 : i+2+end]; varNameRE.MatchString(name) {
				names = append(names, name)
			}
			i += 2 + end
		}
	}
	return names
}

// expandAll expands every string value in c, recording errors with their field paths. Map keys
// are not expanded.
func expandAll(c *Config, lookup LookupFunc, errs *[]error, failed map[string]bool) {
	expandValue(reflect.ValueOf(c).Elem(), "", lookup, func(path string, err error) {
		*errs = append(*errs, fmt.Errorf("%s: %w", path, err))
		failed[path] = true
	})
}

func expandValue(v reflect.Value, path string, lookup LookupFunc, fail func(string, error)) {
	switch v.Kind() { //nolint:exhaustive // only strings and the containers around them are expanded
	case reflect.Pointer:
		if !v.IsNil() {
			expandValue(v.Elem(), path, lookup, fail)
		}
	case reflect.Struct:
		t := v.Type()
		for i := range t.NumField() {
			name, _, _ := strings.Cut(t.Field(i).Tag.Get("yaml"), ",")
			expandValue(v.Field(i), join(path, name), lookup, fail)
		}
	case reflect.Slice:
		for i := range v.Len() {
			expandValue(v.Index(i), fmt.Sprintf("%s[%d]", path, i), lookup, fail)
		}
	case reflect.Map:
		keys := v.MapKeys()
		sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
		for _, k := range keys {
			e := v.MapIndex(k)
			p := join(path, k.String())
			if e.Kind() == reflect.String {
				s, err := Expand(e.String(), lookup)
				if err != nil {
					fail(p, err)
					continue
				}
				v.SetMapIndex(k, reflect.ValueOf(s).Convert(e.Type()))
				continue
			}
			expandValue(e, p, lookup, fail)
		}
	case reflect.String:
		s, err := Expand(v.String(), lookup)
		if err != nil {
			fail(path, err)
			return
		}
		v.SetString(s)
	default:
	}
}

func join(path, name string) string {
	if path == "" {
		return name
	}
	return path + "." + name
}
