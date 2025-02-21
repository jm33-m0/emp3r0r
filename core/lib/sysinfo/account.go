package sysinfo

func HasRoot() bool {
	return crossPlatformHasRoot()
}
