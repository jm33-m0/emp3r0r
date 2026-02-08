package sysinfo

// OSInfo information.
type OSInfo struct {
	Name         string `cbor:"1,keyasint"`
	Vendor       string `cbor:"2,keyasint"`
	Version      string `cbor:"3,keyasint"`
	Release      string `cbor:"4,keyasint"`
	Architecture string `cbor:"5,keyasint"`
	Kernel       string `cbor:"6,keyasint"`
}
