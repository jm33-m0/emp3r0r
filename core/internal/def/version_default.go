//go:build !release

package def

// build.py injects BuildVersion with -ldflags -X. Development and operator
// builds (which do not carry the `release` tag) fall back to the release
// constant so they still report a version. Shipped agent payloads are built
// with the `release` tag and always receive the injected value, so neither this
// fallback nor the const it references contributes a string to the agent binary.
func init() {
	if BuildVersion == "" {
		BuildVersion = Version
	}
}
