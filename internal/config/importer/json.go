package importer

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// object is a decoded JSON object whose keys are matched without regard to case, as
// encoding/json matches struct fields. Two keys that differ only in case are an error, since
// encoding/json lets the later one win. It remembers the keys it was asked for, so the rest can
// be reported.
type object struct {
	path string
	m    map[string]any
	used map[string]bool
}

func newObject(path string, v any) (*object, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: must be an object", path)
	}
	return &object{path: path, m: m, used: map[string]bool{}}, nil
}

// key returns the key in o that matches name, or "" when there is none.
func (o *object) key(name string) (string, error) {
	var found []string
	for k := range o.m {
		if strings.EqualFold(k, name) {
			found = append(found, k)
		}
	}
	switch len(found) {
	case 0:
		return "", nil
	case 1:
		return found[0], nil
	default:
		sort.Strings(found)
		return "", fmt.Errorf("%s: keys %s differ only in case", o.path, strings.Join(found, ", "))
	}
}

// get returns the value of name and whether it is present and not null.
func (o *object) get(name string) (any, bool, error) {
	k, err := o.key(name)
	if err != nil || k == "" {
		return nil, false, err
	}
	o.used[k] = true
	v := o.m[k]
	return v, v != nil, nil
}

func (o *object) sub(name string) string { return o.path + "." + name }

// rest returns the keys that were never asked for, sorted.
func (o *object) rest() []string {
	var keys []string
	for k := range o.m {
		if !o.used[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

func (o *object) object(name string) (*object, error) {
	v, ok, err := o.get(name)
	if err != nil || !ok {
		return nil, err
	}
	return newObject(o.sub(name), v)
}

func (o *object) str(name string) (string, bool, error) {
	v, ok, err := o.get(name)
	if err != nil || !ok {
		return "", false, err
	}
	s, isStr := v.(string)
	if !isStr {
		return "", false, fmt.Errorf("%s: must be a string", o.sub(name))
	}
	return s, true, nil
}

func (o *object) boolean(name string) (value, present bool, err error) {
	v, ok, err := o.get(name)
	if err != nil || !ok {
		return false, false, err
	}
	b, isBool := v.(bool)
	if !isBool {
		return false, false, fmt.Errorf("%s: must be true or false", o.sub(name))
	}
	return b, true, nil
}

func (o *object) strings(name string) ([]string, error) {
	v, ok, err := o.get(name)
	if err != nil || !ok {
		return nil, err
	}
	list, isList := v.([]any)
	if !isList {
		return nil, fmt.Errorf("%s: must be a list of strings", o.sub(name))
	}
	out := make([]string, len(list))
	for i, e := range list {
		s, isStr := e.(string)
		if !isStr {
			return nil, fmt.Errorf("%s[%d]: must be a string", o.sub(name), i)
		}
		out[i] = s
	}
	return out, nil
}

func (o *object) stringMap(name string) (map[string]string, error) {
	sub, err := o.object(name)
	if err != nil || sub == nil {
		return nil, err
	}
	out := make(map[string]string, len(sub.m))
	for k, v := range sub.m {
		s, isStr := v.(string)
		if !isStr {
			return nil, fmt.Errorf("%s.%s: must be a string", sub.path, k)
		}
		out[k] = s
	}
	return out, nil
}

// duration reads an mcp-proxy duration: a string such as "30s", or a number of nanoseconds.
func (o *object) duration(name string) (time.Duration, bool, error) {
	v, ok, err := o.get(name)
	if err != nil || !ok {
		return 0, false, err
	}
	switch x := v.(type) {
	case string:
		d, err := time.ParseDuration(x)
		if err != nil {
			return 0, false, fmt.Errorf("%s: is not a duration", o.sub(name))
		}
		if d < 0 {
			return 0, false, fmt.Errorf("%s: cannot be negative", o.sub(name))
		}
		return d, true, nil
	case json.Number:
		n, err := x.Int64()
		if err != nil || n < 0 {
			return 0, false, fmt.Errorf("%s: is not a duration", o.sub(name))
		}
		return time.Duration(n), true, nil
	default:
		return 0, false, fmt.Errorf("%s: is not a duration", o.sub(name))
	}
}

// integer reads a whole number.
func (o *object) integer(name string) (int64, bool, error) {
	v, ok, err := o.get(name)
	if err != nil || !ok {
		return 0, false, err
	}
	n, isNum := v.(json.Number)
	if !isNum {
		return 0, false, fmt.Errorf("%s: must be a whole number", o.sub(name))
	}
	i, err := n.Int64()
	if err != nil {
		return 0, false, fmt.Errorf("%s: must be a whole number", o.sub(name))
	}
	return i, true, nil
}
