package transport

const (
	// WebRoot root path of APIs
	WebRoot = "api"
	// CheckInAPI agent send POST to this API to report its system info
	CheckInAPI = WebRoot + "/checkin"
	// MsgAPI duplex tunnel between agent and cc
	MsgAPI = WebRoot + "/msg"
	// ReverseShellAPI duplex tunnel between agent and cc
	ReverseShellAPI = WebRoot + "/rshell"
	// PortMappingAPI proxy interface
	PortMappingAPI = WebRoot + "/proxy"
	// Upload2AgentAPI file transfer
	Upload2AgentAPI = WebRoot + "/ftp"
	// DownloadFile2AgentAPI host some files
	DownloadFile2AgentAPI = WebRoot + "/www"
	// Static hosting
	WWW = "/www/"

	// OperatorRoot root path of control APIs
	OperatorRoot = "operator"
	// OperatorMsgTunnel
	OperatorMsgTunnel = OperatorRoot + "/msg_tunnel"
	// OperatorSetActiveAgent
	OperatorSetActiveAgent = OperatorRoot + "/set_active_agent"
	// OperatorListConnectedAgents
	OperatorListConnectedAgents = OperatorRoot + "/list_connected_agents"
	// OperatorSendCommand
	OperatorSendCommand = OperatorRoot + "/send_command"
)
