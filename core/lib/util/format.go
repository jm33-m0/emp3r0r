package util

import "fmt"

// FormatBytes renders a byte count with binary units and a compact number of
// significant digits, e.g. "512 B", "1.5 KiB", "9.2 MiB", "120 MiB".
func FormatBytes(n int64) string {
	if n <= 0 {
		return "0 B"
	}
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	value := float64(n)
	units := [...]string{"KiB", "MiB", "GiB", "TiB", "PiB", "EiB"}
	unit := units[0]
	for _, u := range units {
		value /= 1024
		unit = u
		if value < 1024 {
			break
		}
	}
	if value >= 10 {
		return fmt.Sprintf("%.0f %s", value, unit)
	}
	return fmt.Sprintf("%.1f %s", value, unit)
}
