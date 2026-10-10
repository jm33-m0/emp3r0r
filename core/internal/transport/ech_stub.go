//go:build no_doh || no_ech

package transport

import "context"

// echConfigList is the disabled-ECH stub: ECH needs the DoH resolver and a
// build without the no_ech tag, so the TLS dialers always connect without ECH.
func echConfigList(context.Context) ([]byte, bool, error) {
	return nil, false, nil
}
