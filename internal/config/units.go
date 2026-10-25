package config

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"go.yaml.in/yaml/v3"
)

// Duration is a time.Duration written as a string with a unit, such as "30s" or "2m". A bare
// number is rejected, since it is ambiguous.
type Duration time.Duration

// D returns d as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode || n.Tag != "!!str" {
		return fmt.Errorf(`line %d: a duration is a string with a unit, such as "30s"`, n.Line)
	}
	v, err := time.ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf(`line %d: a duration is a string with a unit, such as "30s"`, n.Line)
	}
	if v < 0 {
		return fmt.Errorf("line %d: a duration cannot be negative", n.Line)
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
	msg := fmt.Sprintf(`line %d: a size is a string with a unit B, KiB, MiB or GiB, such as "16MiB"`, n.Line)
	if n.Kind != yaml.ScalarNode || n.Tag != "!!str" {
		return errors.New(msg)
	}
	v, err := ParseByteSize(n.Value)
	if err != nil {
		return errors.New(msg)
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
