//go:build windows

package coffloader

// PreExecHook is called on the BOF/DLL execution thread before the entry
// point is invoked. The agent wires this to priv.ImpersonateThread.
var PreExecHook func(token uintptr)

// PostExecHook is called after the BOF/DLL entry point returns. The agent
// wires this to priv.RevertThread.
var PostExecHook func()
