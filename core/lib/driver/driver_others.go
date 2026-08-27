//go:build !windows

package driver

import "errors"

var errNotSupported = errors.New("kernel driver loading not supported on non-windows platforms")

// LoadSignedDriver stub for non-windows platforms
func LoadSignedDriver(driverPath, serviceName string) error {
	return errNotSupported
}

// LoadSignedDriverBytes stub for non-windows platforms
func LoadSignedDriverBytes(b []byte, serviceName string) error {
	return errNotSupported
}

// UnloadDriver stub for non-windows platforms
func UnloadDriver(serviceName string) error {
	return errNotSupported
}

// IsLoaded stub for non-windows platforms
func IsLoaded(serviceName string) bool {
	return false
}

// IsDriverSigned stub for non-windows platforms
func IsDriverSigned(path string) (bool, error) {
	return false, errNotSupported
}
