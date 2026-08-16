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

// OperatorIdleConfig updates server-side operator-idle settings.
type OperatorIdleConfig struct {
	OperatorIdleTimeout int `cbor:"1,keyasint"` // seconds; 0 disables idle-based rejection
}

// FTPStreamRequest is the request to register an FTP stream
type FTPStreamRequest struct {
	Token        string               `cbor:"1,keyasint"`
	FilePath     string               `cbor:"2,keyasint"`
	ExpectedSize int64                `cbor:"3,keyasint"`
	Checksum     string               `cbor:"4,keyasint"`
	Claim        *OperatorStreamClaim `cbor:"5,keyasint"`
}
