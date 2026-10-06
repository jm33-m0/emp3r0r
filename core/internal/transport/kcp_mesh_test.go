//go:build !no_mesh && !no_kcp

package transport

// meshKCPTransportCompiled reports whether the KCP mesh transport is part of
// this build. Tests use it to decide whether "kcp" must be registered.
const meshKCPTransportCompiled = true
