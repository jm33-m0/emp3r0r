package def

import (
	"io"
	"net/http"
)

var (
	// Magic String, this is decided at build time
	// use: C2 message construction and encryption
	MagicString = "64781530-1475-4cf8-950c-dcdf4c619dbc"

	// QUICKey is the static key that seeds the QUIC datagram obfuscation.
	// Like MagicString it is patched at build time via -ldflags -X, so a C2 and
	// its agents built from the same batch always agree. When empty, the key is
	// derived from MagicString instead.
	QUICKey = ""

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

// Version is the release version. release-please (release-type: go) updates
// this exact declaration, so keep the `const Version = "x.y.z"` form.
const Version = "5.2.2"

// BuildVersion is the version a running binary reports: the release version
// plus the build timestamp, injected at build time with -ldflags -X. The zero
// value means "not injected"; non-release builds fill it from Version.
var BuildVersion string

const (
	// Unknown
	Unknown = "Unknown"
)
