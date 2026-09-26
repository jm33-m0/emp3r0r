package transport

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// plausibleCertOrgs are generic infrastructure names shared by every generated
// certificate. A constant organization (or a tiny fixed set) is a stable
// fingerprint, so callers pick one at random.
var plausibleCertOrgs = []string{
	"System Infrastructure",
	"Kubernetes Cluster",
	"Internal Services",
	"Mesh Node",
	"Cloud Platform",
	"Enterprise Services",
	"Network Operations",
	"Data Services",
	"Identity Services",
	"Platform Engineering",
	"Managed Hosting",
	"Edge Network",
}

// randomCertSerial returns a random positive serial number. A constant serial
// (e.g. 1) is itself a fingerprint.
func randomCertSerial() *big.Int {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil || serial.Sign() == 0 {
		// crypto/rand is unavailable; a time-derived value is still unique per
		// certificate and preferable to a constant.
		return big.NewInt(time.Now().UnixNano())
	}
	return serial
}

// randomCertOrg returns a random plausible organization name.
func randomCertOrg() string {
	return plausibleCertOrgs[util.RandInt(0, len(plausibleCertOrgs))]
}

// randomCertCN returns a random node-style common name.
func randomCertCN() string {
	return fmt.Sprintf("node-%x", util.RandBytes(2))
}

// randomCertValidity returns a randomized validity window. Fixed 10-year
// validity is a fingerprint; leaf certs get 1-2 years and CAs 2-5 years.
func randomCertValidity(isCA bool) (notBefore, notAfter time.Time) {
	now := time.Now()
	notBefore = now.Add(-time.Duration(util.RandInt(1, 72)) * time.Hour)
	days := util.RandInt(365, 730)
	if isCA {
		days = util.RandInt(730, 1826)
	}
	return notBefore, now.Add(time.Duration(days) * 24 * time.Hour)
}
