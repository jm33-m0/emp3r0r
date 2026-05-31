/*
Package def defines shared data structures and constants.

C2Commands (prefixed with "!") are internal APIs used by the operator
for automated tasks like auto-completion and status tracking.
*/
package def

// C2Commands are internal APIs used by the operator
const (
	C2CmdListDir      = "!ls_dir" // API for path auto-completion
	C2CmdCleanLog     = "!clean_log"
	C2CmdCustomModule = "!custom_module"

	C2CmdStat           = "!stat"
	C2CmdListener       = "!listener"
	C2CmdFileServer     = "!file_server"
	C2CmdFileDownloader = "!file_downloader"

	C2CmdSysInfo = "!sysinfo"
)
