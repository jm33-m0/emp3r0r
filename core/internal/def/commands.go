/*
Package def defines shared data structures and constants.

C2Commands (prefixed with "!") are internal APIs used by the operator
for automated tasks like auto-completion and status tracking.
*/
package def

// C2Commands are internal APIs used by the operator
const (
	C2CmdListDir      = "!ls_dir" // API for path auto-completion
	C2CmdStealToken   = "!steal_token"
	C2CmdListTokens   = "!list_tokens"   // API for token auto-completion
	C2CmdListSessions = "!list_sessions" // API for logon session auto-completion
	C2CmdCustomModule = "!custom_module"

	C2CmdStat           = "!stat"
	C2CmdListener       = "!listener"
	C2CmdFileDownloader = "!file_downloader"

	// C2CmdProxyStart orders the agent to dial a target and open a dedicated
	// C2 relay stream (Proxy route) so the C2 can forward SOCKS5 traffic to it.
	C2CmdProxyStart = "!proxy_start"

	// C2CmdDNSQuery orders the agent to resolve a DNS question carried in a
	// raw RFC 1035 DNS query packet (base64 in --query). The agent answers
	// with a complete DNS response packet (raw bytes) as if it were a
	// recursive DNS server for the C2-side SOCKS5/DNS helper: DNS for
	// agent-side networks must be resolved by the agent, because only the
	// agent can reach those names.
	C2CmdDNSQuery = "!dns_query"
)
