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
	// OperatorForgetAgent
	OperatorForgetAgent = OperatorRoot + "/forget_agent"
	// OperatorGetCA
	OperatorGetCA = OperatorRoot + "/get_ca"
	// OperatorSignAgent
	OperatorSignAgent = OperatorRoot + "/sign_agent"
	// OperatorRegisterFTPStream
	OperatorRegisterFTPStream = OperatorRoot + "/register_ftp_stream"
	// OperatorUnregisterFTPStream
	OperatorUnregisterFTPStream = OperatorRoot + "/unregister_ftp_stream"
	// OperatorUpdateConfig
	OperatorUpdateConfig = OperatorRoot + "/update_config"
	// OperatorResume
	OperatorResume = OperatorRoot + "/resume"
	// OperatorSocks5Start starts a C2-resident SOCKS5 pivot listener bound to an agent
	OperatorSocks5Start = OperatorRoot + "/socks5_start"
	// OperatorSocks5Stop stops a C2-resident SOCKS5 pivot listener
	OperatorSocks5Stop = OperatorRoot + "/socks5_stop"
	// OperatorSocks5List lists running C2-resident SOCKS5 pivots
	OperatorSocks5List = OperatorRoot + "/socks5_list"
)
