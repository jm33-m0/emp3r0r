//go:build !with_doh || !with_ech

package transport

import "context"

// echConfigList is the disabled-ECH stub: ECH needs the DoH resolver and a
// build with the with_ech tag, so the TLS dialers always connect without ECH.
func echConfigList(context.Context) ([]byte, bool, error) {
	return nil, false, nil
}
