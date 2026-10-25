//go:build !linux

package procutil

// SetNonDumpable does nothing outside Linux.
func SetNonDumpable() error { return nil }

func setOOMScoreAdj(int, int) error { return nil }

// Reaper does nothing outside Linux.
type Reaper struct{}

// EnableSubreaper does nothing outside Linux: there is no child subreaper.
func EnableSubreaper() (*Reaper, error) { return &Reaper{}, nil }

// Close does nothing.
func (*Reaper) Close() {}
