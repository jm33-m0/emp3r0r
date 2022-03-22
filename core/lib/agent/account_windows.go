//go:build windows
// +build windows

package agent

import (
	"log"

	"golang.org/x/sys/windows"
)

func crossPlatformHasRoot() bool {
	token := windows.Token(0) // current user

	return IsUserPrivileged(token)
}

// Given a user token, check if it's privileged
func IsUserPrivileged(token windows.Token) (result bool) {
	var sid *windows.SID

	// Although this looks scary, it is directly copied from the
	// official windows documentation. The Go API for this is a
	// direct wrap around the official C++ API.
	// See https://docs.microsoft.com/en-us/windows/desktop/api/securitybaseapi/nf-securitybaseapi-checktokenmembership
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid)
	if err != nil {
		log.Printf("SID Error: %s", err)
		return false
	}
	result, err = token.IsMember(sid)
	if err != nil {
		log.Printf("Token Membership Error: %s", err)
		return
	}

	return result || token.IsElevated()
}
