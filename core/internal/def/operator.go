package def

// Operation is a command or module operation to be executed on C2 server
type Operation struct {
	AgentTag   string  `cbor:"1,keyasint"` // the target agent
	Action     string  `cbor:"2,keyasint"` // the action to perform: "command" or "module"
	Command    *string `cbor:"3,keyasint"` // the command to send to the agent (if action is "command")
	CommandID  *string `cbor:"4,keyasint"` // the command ID (if action is "command")
	ModuleName *string `cbor:"5,keyasint"` // the module (if action is "module")
	SetOption  *string `cbor:"6,keyasint"` // the option to set (if action is "module")
	SetValue   *string `cbor:"7,keyasint"` // the value to set (if action is "module")
}

// IsOptionSet checks if a specific option is set
func (op *Operation) IsOptionSet(option string) bool {
	switch option {
	case "command":
		return op.Command != nil
	case "command_id":
		return op.CommandID != nil
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
