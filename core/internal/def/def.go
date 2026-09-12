package def

import (
	"io"
	"net/http"
)

var (
	// Magic String, this is decided at build time
	// use: C2 message construction and encryption
	MagicString = "64781530-1475-4cf8-950c-dcdf4c619dbc"

	// HTTPClient handles agent's http communication
	HTTPClient *http.Client

	// CCMsgConn the connection to CC, for JSON message-based communication
	CCMsgConn io.ReadWriteCloser

	// will be updated by ReadJSONConfig

	// CCAddress is the address of the CC server
	// in form https://host:port
	CCAddress = ""

	// AESPassword generated from Tag -> md5sum, type: []byte
	AESPassword []byte
)

// Build
var (
	// Version hardcoded version string
	Version = "unknown"
)

const (
	// Unknown
	Unknown = "Unknown"
)
