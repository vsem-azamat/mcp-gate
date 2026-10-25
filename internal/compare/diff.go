package compare

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
)

// Side names one of the two compared sources.
type Side string

// The two sources.
const (
	SideA Side = "a"
	SideB Side = "b"
)

// Difference is one way two catalogs of a server differ.
type Difference struct {
	Kind Kind
	ID   string
	// OnlyIn is set when the entry is in one source only.
	OnlyIn Side
	// Duplicate is set to the source that lists the identifier more than once.
	Duplicate Side
	// Field is the differing field when the entry is in both sources; A and B are its canonical
	// values, nil when the field is absent.
	Field string
	A, B  json.RawMessage
}

// absent is how a missing field is shown.
const absent = "(absent)"

// String is a one-line description, followed by the two values for a field difference.
func (d Difference) String() string {
	head := fmt.Sprintf("%s %q", d.Kind, d.ID)
	switch {
	case d.Duplicate != "":
		return fmt.Sprintf("%s: listed more than once in %s", head, d.Duplicate)
	case d.OnlyIn != "":
		return fmt.Sprintf("%s: only in %s", head, d.OnlyIn)
	default:
		return fmt.Sprintf("%s: %s differs\n  a: %s\n  b: %s", head, d.Field, show(d.A), show(d.B))
	}
}

func show(v json.RawMessage) string {
	if v == nil {
		return absent
	}
	return string(v)
}

// Diff returns the differences between catalogs a and b, ordered by kind, then identifier, then
// field.
func Diff(a, b Catalog) ([]Difference, error) {
	la, err := a.lists()
	if err != nil {
		return nil, fmt.Errorf("a: %w", err)
	}
	lb, err := b.lists()
	if err != nil {
		return nil, fmt.Errorf("b: %w", err)
	}
	var out []Difference
	for i := range la {
		out = append(out, diffList(la[i], lb[i])...)
	}
	return out, nil
}

func diffList(a, b list) []Difference {
	var out []Difference
	ia, dupA := index(a.entries)
	ib, dupB := index(b.entries)
	for _, id := range dupA {
		out = append(out, Difference{Kind: a.kind, ID: id, Duplicate: SideA})
	}
	for _, id := range dupB {
		out = append(out, Difference{Kind: a.kind, ID: id, Duplicate: SideB})
	}
	ids := slices.Collect(maps.Keys(ia))
	for id := range ib {
		if _, ok := ia[id]; !ok {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	for _, id := range ids {
		ea, inA := ia[id]
		eb, inB := ib[id]
		switch {
		case !inB:
			out = append(out, Difference{Kind: a.kind, ID: id, OnlyIn: SideA})
		case !inA:
			out = append(out, Difference{Kind: a.kind, ID: id, OnlyIn: SideB})
		default:
			out = append(out, diffFields(a.kind, id, ea.fields, eb.fields)...)
		}
	}
	slices.SortStableFunc(out, func(x, y Difference) int { return strings.Compare(x.ID, y.ID) })
	return out
}

// index maps each identifier to its first entry and returns the identifiers listed more than once.
func index(entries []entry) (map[string]entry, []string) {
	m := make(map[string]entry, len(entries))
	var dup []string
	for _, e := range entries {
		if _, ok := m[e.id]; ok {
			if !slices.Contains(dup, e.id) {
				dup = append(dup, e.id)
			}
			continue
		}
		m[e.id] = e
	}
	return m, dup
}

func diffFields(kind Kind, id string, a, b map[string]json.RawMessage) []Difference {
	keys := slices.Collect(maps.Keys(a))
	for k := range b {
		if _, ok := a[k]; !ok {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	var out []Difference
	for _, k := range keys {
		// canonical never returns an empty value, so an absent field never equals a present one.
		if va, vb := a[k], b[k]; !bytes.Equal(va, vb) {
			out = append(out, Difference{Kind: kind, ID: id, Field: k, A: va, B: vb})
		}
	}
	return out
}
