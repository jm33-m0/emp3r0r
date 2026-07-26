package script

import (
	"fmt"

	"go.starlark.net/starlark"
)

// AgentProxy defines an interface for proxying agent functions to Starlark.
// This interface uses standard Go types so lib/script has zero imports of agent packages.
type AgentProxy interface {
	GatherSystemDetails() (map[string]any, error)
	GetUptime() string
	GetUserAndGroups() (string, string)
	GetContainerName() string
	HasRoot() bool
	ExecuteShell(scriptBytes []byte, argv, env []string) (string, error)
	ExecutePython(scriptBytes []byte, argv, env []string) (string, error)
	ExecutePowerShell(scriptBytes []byte, argv, env []string) (string, error)
	ExecuteBatch(scriptBytes []byte, argv, env []string) (string, error)
	SignWithAgentKey(data []byte) ([]byte, error)
	GetTag() string
	GetUUID() string
	TouchFile(path string) error
	CopyFileTimes(src, dst string) error
	FetchFile(peer, fileToDownload, path, checksum string) ([]byte, error)
}

// AgentModule represents the Starlark module object for "agent"
type AgentModule struct {
	attrs starlark.StringDict
}

func NewAgentModule(attrs starlark.StringDict) *AgentModule {
	return &AgentModule{attrs: attrs}
}

func (m *AgentModule) String() string        { return "<module 'agent'>" }
func (m *AgentModule) Type() string          { return "module" }
func (m *AgentModule) Freeze()               {}
func (m *AgentModule) Truth() starlark.Bool  { return true }
func (m *AgentModule) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable type: module") }

func (m *AgentModule) Attr(name string) (starlark.Value, error) {
	if val, ok := m.attrs[name]; ok {
		return val, nil
	}
	return nil, nil
}

func (m *AgentModule) AttrNames() []string {
	names := make([]string, 0, len(m.attrs))
	for name := range m.attrs {
		names = append(names, name)
	}
	return names
}

var currentAgentProxy AgentProxy

// SetAgentProxy allows the agent package to patch script package with its AgentProxy implementation.
func SetAgentProxy(proxy AgentProxy) {
	currentAgentProxy = proxy
}

// GetAgentProxy returns the active AgentProxy instance.
func GetAgentProxy() AgentProxy {
	return currentAgentProxy
}

var agentAPIs = map[string]StarlarkAPI{
	"sys_info":        starlarkAgentSysInfo,
	"sysinfo":         starlarkAgentSysInfo,
	"uptime":          starlarkAgentUptime,
	"user":            starlarkAgentUser,
	"container":       starlarkAgentContainer,
	"has_root":        starlarkAgentHasRoot,
	"is_root":         starlarkAgentHasRoot,
	"exec_shell":      starlarkAgentExecShell,
	"exec_python":     starlarkAgentExecPython,
	"exec_powershell": starlarkAgentExecPowerShell,
	"exec_batch":      starlarkAgentExecBatch,
	"sign":            starlarkAgentSign,
	"tag":             starlarkAgentTag,
	"uuid":            starlarkAgentUUID,
	"touch_file":      starlarkAgentTouchFile,
	"fetch_file":      starlarkAgentFetchFile,
}

func getAgentModuleDict() starlark.StringDict {
	d := make(starlark.StringDict, len(agentAPIs))
	for name, fn := range agentAPIs {
		d[name] = starlark.NewBuiltin("agent."+name, fn)
	}
	return d
}

func init() {
	for name, fn := range agentAPIs {
		RegisterAPI("agent_"+name, fn)
	}
}

func mapToStarlarkValue(v any) (starlark.Value, error) {
	switch val := v.(type) {
	case nil:
		return starlark.None, nil
	case starlark.Value:
		return val, nil
	case string:
		return starlark.String(val), nil
	case bool:
		return starlark.Bool(val), nil
	case int:
		return starlark.MakeInt(val), nil
	case int64:
		return starlark.MakeInt64(val), nil
	case uint64:
		return starlark.MakeUint64(val), nil
	case float64:
		return starlark.Float(val), nil
	case []byte:
		return starlark.Bytes(val), nil
	case []string:
		list := starlark.NewList(nil)
		for _, s := range val {
			list.Append(starlark.String(s))
		}
		return list, nil
	case []any:
		list := starlark.NewList(nil)
		for _, elem := range val {
			stElem, err := mapToStarlarkValue(elem)
			if err != nil {
				return starlark.None, err
			}
			list.Append(stElem)
		}
		return list, nil
	case map[string]any:
		d := starlark.NewDict(len(val))
		for k, elem := range val {
			stElem, err := mapToStarlarkValue(elem)
			if err != nil {
				return starlark.None, err
			}
			_ = d.SetKey(starlark.String(k), stElem)
		}
		return d, nil
	default:
		return starlark.String(fmt.Sprintf("%v", v)), nil
	}
}

func starlarkAgentSysInfo(_ *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
	if currentAgentProxy == nil {
		return starlark.None, fmt.Errorf("agent_sys_info: agent proxy is not registered")
	}
	detailsMap, err := currentAgentProxy.GatherSystemDetails()
	if err != nil {
		return starlark.None, fmt.Errorf("agent_sys_info: %w", err)
	}
	return mapToStarlarkValue(detailsMap)
}

func starlarkAgentUptime(_ *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
	if currentAgentProxy == nil {
		return starlark.String(""), nil
	}
	return starlark.String(currentAgentProxy.GetUptime()), nil
}

func starlarkAgentUser(_ *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
	if currentAgentProxy == nil {
		d := starlark.NewDict(2)
		_ = d.SetKey(starlark.String("user"), starlark.String(""))
		_ = d.SetKey(starlark.String("groups"), starlark.String(""))
		return d, nil
	}
	u, g := currentAgentProxy.GetUserAndGroups()
	d := starlark.NewDict(2)
	_ = d.SetKey(starlark.String("user"), starlark.String(u))
	_ = d.SetKey(starlark.String("groups"), starlark.String(g))
	return d, nil
}

func starlarkAgentContainer(_ *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
	if currentAgentProxy == nil {
		return starlark.String(""), nil
	}
	return starlark.String(currentAgentProxy.GetContainerName()), nil
}

func starlarkAgentHasRoot(_ *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
	if currentAgentProxy == nil {
		return starlark.Bool(false), nil
	}
	return starlark.Bool(currentAgentProxy.HasRoot()), nil
}

func starlarkAgentExecHelper(fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple, execFn func([]byte, []string, []string) (string, error)) (starlark.Value, error) {
	if currentAgentProxy == nil {
		return starlark.None, fmt.Errorf("%s: agent proxy is not registered", fn.Name())
	}
	var scriptStr string
	var argsList, envList *starlark.List
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "script", &scriptStr, "args?", &argsList, "env?", &envList); err != nil {
		return starlark.None, err
	}
	out, err := execFn([]byte(scriptStr), starlarkListToStrings(argsList), starlarkListToStrings(envList))
	if err != nil {
		return starlark.String(out), fmt.Errorf("%s: %w (output: %s)", fn.Name(), err, out)
	}
	return starlark.String(out), nil
}

func starlarkListToStrings(list *starlark.List) []string {
	if list == nil {
		return nil
	}
	res := make([]string, 0, list.Len())
	for i := 0; i < list.Len(); i++ {
		if s, ok := starlark.AsString(list.Index(i)); ok {
			res = append(res, s)
		}
	}
	return res
}

func starlarkAgentExecShell(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return starlarkAgentExecHelper(fn, args, kwargs, currentAgentProxy.ExecuteShell)
}

func starlarkAgentExecPython(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return starlarkAgentExecHelper(fn, args, kwargs, currentAgentProxy.ExecutePython)
}

func starlarkAgentExecPowerShell(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return starlarkAgentExecHelper(fn, args, kwargs, currentAgentProxy.ExecutePowerShell)
}

func starlarkAgentExecBatch(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return starlarkAgentExecHelper(fn, args, kwargs, currentAgentProxy.ExecuteBatch)
}

func starlarkAgentSign(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if currentAgentProxy == nil {
		return starlark.None, fmt.Errorf("agent_sign: agent proxy is not registered")
	}
	var dataVal starlark.Value
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "data", &dataVal); err != nil {
		return starlark.None, err
	}
	var data []byte
	if s, ok := starlark.AsString(dataVal); ok {
		data = []byte(s)
	} else if bytesVal, ok := dataVal.(starlark.Bytes); ok {
		data = []byte(bytesVal)
	} else {
		return starlark.None, fmt.Errorf("agent_sign argument must be string or bytes")
	}
	sig, err := currentAgentProxy.SignWithAgentKey(data)
	if err != nil {
		return starlark.None, fmt.Errorf("agent_sign: %w", err)
	}
	return starlark.Bytes(sig), nil
}

func starlarkAgentTag(_ *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
	if currentAgentProxy == nil {
		return starlark.String(""), nil
	}
	return starlark.String(currentAgentProxy.GetTag()), nil
}

func starlarkAgentUUID(_ *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
	if currentAgentProxy == nil {
		return starlark.String(""), nil
	}
	return starlark.String(currentAgentProxy.GetUUID()), nil
}

func starlarkAgentTouchFile(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if currentAgentProxy == nil {
		return starlark.None, fmt.Errorf("agent_touch_file: agent proxy is not registered")
	}
	var path string
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "path", &path); err != nil {
		return starlark.None, err
	}
	if err := currentAgentProxy.TouchFile(path); err != nil {
		return starlark.None, fmt.Errorf("agent_touch_file %s: %w", path, err)
	}
	return starlark.None, nil
}

func starlarkAgentFetchFile(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if currentAgentProxy == nil {
		return starlark.None, fmt.Errorf("agent_fetch_file: agent proxy is not registered")
	}
	var fileToDownload string
	var peerStr string
	var pathStr string
	var checksumStr string
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "file_to_download", &fileToDownload, "peer?", &peerStr, "path?", &pathStr, "checksum?", &checksumStr); err != nil {
		return starlark.None, err
	}
	data, err := currentAgentProxy.FetchFile(peerStr, fileToDownload, pathStr, checksumStr)
	if err != nil {
		return starlark.None, fmt.Errorf("fetch_file %s: %w", fileToDownload, err)
	}
	if pathStr != "" {
		return starlark.None, nil
	}
	return starlark.Bytes(data), nil
}
