package def

// Operation is a command or module operation to be executed on C2 server
type Operation struct {
	AgentTag   string  `cbor:"1,keyasint"` // the target agent
	Action     string  `cbor:"2,keyasint"` // the action to perform: "command" or "module"
	Command    *string `cbor:"3,keyasint"` // the command to send to the agent (if action is "command")
	JobID      *string `cbor:"8,keyasint"` // the job ID (if action is "command")
	ModuleName *string `cbor:"5,keyasint"` // the module (if action is "module")
	SetOption  *string `cbor:"6,keyasint"` // the option to set (if action is "module")
	SetValue   *string `cbor:"7,keyasint"` // the value to set (if action is "module")
}

// IsOptionSet checks if a specific option is set
func (op *Operation) IsOptionSet(option string) bool {
	switch option {
	case "command":
		return op.Command != nil
	case "job_id":
		return op.JobID != nil
	case "module_name":
		return op.ModuleName != nil
	case "set_option":
		return op.SetOption != nil
	case "set_value":
		return op.SetValue != nil
	default:
		return false
	}
}

// SignRequest is the request to sign data
type SignRequest struct {
	Content []byte `cbor:"1,keyasint"` // content to sign (usually UUID)
}

// PortFwdRequest is the request to register a port mapping
type PortFwdRequest struct {
	SessionID   string `cbor:"1,keyasint"`
	Lport       string `cbor:"2,keyasint"`
	To          string `cbor:"3,keyasint"`
	Description string `cbor:"4,keyasint"`
	Protocol    string `cbor:"5,keyasint"`
	AgentTag    string `cbor:"6,keyasint"` // Add Agent Tag for context
	IsReverse   bool   `cbor:"7,keyasint"`
}

// FTPStreamRequest is the request to register an FTP stream
type FTPStreamRequest struct {
	Token    string `cbor:"1,keyasint"`
	FilePath string `cbor:"2,keyasint"`
}
