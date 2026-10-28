package config

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// decodeError is the error of a value that does not decode, as a *yaml.TypeError, so that the
// decoder goes on and Parse reports it with every other problem.
func decodeError(format string, args ...any) error {
	return &yaml.TypeError{Errors: []string{fmt.Sprintf(format, args...)}}
}

// FileMode is a file's permission bits, written in octal: 0600, "0600" or "0o600".
type FileMode uint32

// UnmarshalYAML implements yaml.Unmarshaler. It reads the scalar's text as octal whatever its
// YAML type, since YAML reads 0600 as a decimal or octal number depending on the version.
func (m *FileMode) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode {
		return decodeError("line %d: a file mode is octal, such as 0600", n.Line)
	}
	v, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimPrefix(n.Value, "0o"), "0O"), 8, 32)
	if err != nil {
		return decodeError("line %d: a file mode is octal, such as 0600", n.Line)
	}
	*m = FileMode(v)
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (m FileMode) MarshalYAML() (any, error) { return fmt.Sprintf("%04o", uint32(m)), nil }

// Duration is a time.Duration written as a string with a unit, such as "30s" or "2m". A bare
// number is rejected, since it is ambiguous.
type Duration time.Duration

// D returns d as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode || n.Tag != "!!str" {
		return decodeError(`line %d: a duration is a string with a unit, such as "30s"`, n.Line)
	}
	v, err := time.ParseDuration(n.Value)
	if err != nil {
		return decodeError(`line %d: a duration is a string with a unit, such as "30s"`, n.Line)
	}
	if v < 0 {
		return decodeError("line %d: a duration cannot be negative", n.Line)
	}
	*d = Duration(v)
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (d Duration) MarshalYAML() (any, error) { return FormatDuration(time.Duration(d)), nil }

// FormatDuration writes d the way the config reads it, without trailing zero units ("2m", not
// "2m0s").
func FormatDuration(d time.Duration) string {
	s := d.String()
	for _, suffix := range []string{"m0s", "h0m"} {
		if len(s) > len(suffix) && s[len(s)-len(suffix):] == suffix {
			s = s[:len(s)-len(suffix)+1]
		}
	}
	return s
}

// ByteSize is a number of bytes written with a binary unit: "512KiB", "16MiB", "1GiB" or
// "100B".
type ByteSize int64

var byteSizeRE = regexp.MustCompile(`^([0-9]+)(B|KiB|MiB|GiB)$`)

var byteUnits = map[string]int64{"B": 1, "KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30}

// UnmarshalYAML implements yaml.Unmarshaler.
func (b *ByteSize) UnmarshalYAML(n *yaml.Node) error {
	const msg = `line %d: a size is a string with a unit B, KiB, MiB or GiB, such as "16MiB"`
	if n.Kind != yaml.ScalarNode || n.Tag != "!!str" {
		return decodeError(msg, n.Line)
	}
	v, err := ParseByteSize(n.Value)
	if err != nil {
		return decodeError(msg, n.Line)
	}
	*b = v
	return nil
}

// ParseByteSize parses a size such as "16MiB".
func ParseByteSize(s string) (ByteSize, error) {
	m := byteSizeRE.FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	unit := byteUnits[m[2]]
	if err != nil || n > (1<<62)/unit {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	return ByteSize(n * unit), nil
}

// MarshalYAML implements yaml.Marshaler.
func (b ByteSize) MarshalYAML() (any, error) { return b.String(), nil }

// String writes b with the largest unit that divides it.
func (b ByteSize) String() string {
	for _, u := range []string{"GiB", "MiB", "KiB"} {
		if f := byteUnits[u]; b != 0 && int64(b)%f == 0 {
			return strconv.FormatInt(int64(b)/f, 10) + u
		}
	}
	return strconv.FormatInt(int64(b), 10) + "B"
}
