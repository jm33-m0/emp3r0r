package def

// OperatorMsg is the C2 <-> operator message-tunnel envelope.
//
// It is deliberately separate from MsgTunData: operator relay frames must not
// carry agent-only fields (ephemeral key, peer list, token) and agent frames
// must not carry relay-only semantics.
type OperatorMsg struct {
	JobID    string   `cbor:"1,keyasint"` // job correlation, when relaying a command result
	CmdSlice []string `cbor:"2,keyasint"` // command argv, when relaying a command result
	Response []byte   `cbor:"3,keyasint"` // relay payload / operator notification
	Tag      string   `cbor:"4,keyasint"` // relay tag or notification type
}
