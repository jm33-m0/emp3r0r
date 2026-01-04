package live

import (
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
)

// LoadCACrt2RuntimeConfig CA cert to runtime config
func LoadCACrt2RuntimeConfig() error {
	err := transport.LoadCACrt()
	if err != nil {
		return err
	}
	RuntimeConfig.CAPEM = string(transport.CACrtPEM)
	RuntimeConfig.CAFingerprint = transport.GetFingerprint(transport.CaCrtFile)
	return nil
}
