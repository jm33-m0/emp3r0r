// Package paths holds C2/operator-side filesystem locations.
//
// It is deliberately separate from internal/live. The agent imports live, so a
// string defined there is linked into every agent payload; keeping the branded
// scratch path here means only C2 and operator builds carry it.
package paths

// Temp is the C2 scratch directory.
const Temp = "/tmp/emp3r0r/"

// WWWRoot hosts static files (modules, stagers, operator downloads) served to
// agents and operators. It is a var, not a const, so tests can redirect it.
var WWWRoot = Temp + "www/"
