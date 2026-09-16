// Package modconfig parses emp3r0r module manifests (config.json) and turns
// operator-supplied flag values into a fully resolved invocation. It is the
// single source of truth for module parameter typing: the C2 and the
// standalone debugging tools (cmd/bofrunner) both build their arguments
// through it, so a parameter declared once behaves identically everywhere.
package modconfig

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/coffloader"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// ReadConfigs reads config.json which may define one or more modules.
//
// JSON format (unified)
// ─────────────────────
//
//	{
//	  "name": "hello_linux",
//	  "parameters": [
//	    { "name":"who", "description":"...", "default":"World",
//	      "type":"cstr", "required":false }
//	  ],
//	  "agent_config": { "type":"coff", ... },
//	  "invocation":  { "coff_export":"go" }
//	}
//
// The "type" field in each parameter is the single source of truth for both
// input validation (C2 side) and COFF wire-packing (agent side).
func ReadConfigs(file string) (configs []*def.ModuleConfig, err error) {
	// optionJSON is the unified parameter declaration.
	type optionJSON struct {
		Name     string   `json:"name"`
		Desc     string   `json:"description"`
		Val      string   `json:"default"`
		Vals     []string `json:"choices"`
		Type     string   `json:"type"`
		Required bool     `json:"required"`
		Pattern  string   `json:"pattern"`
		Encoding string   `json:"encoding"`
		Secret   bool     `json:"secret"`
		Min      *float64 `json:"min"`
		Max      *float64 `json:"max"`
		ArgvFlag string   `json:"argv_flag"`
	}

	type invocationArgJSON struct {
		Literal string `json:"literal"`
		Flag    string `json:"flag"`
	}

	type invocationJSON struct {
		Argv           []invocationArgJSON `json:"argv"`
		StdinParam     string              `json:"stdin_param"`
		TimeoutSeconds int                 `json:"timeout_seconds"`
		CoffExport     string              `json:"coff_export"`
		DllExport      string              `json:"dll_export"`
		DllEntry       string              `json:"dll_entry"`
		DllFileParam   string              `json:"dll_file_param"`
	}

	type agentConfigJSON struct {
		Exec          string   `json:"exec"`
		Files         []string `json:"files"`
		InMemory      bool     `json:"in_memory"`
		Type          string   `json:"type"`
		IsInteractive bool     `json:"interactive"`
		WorkDir       string   `json:"work_dir"`
		NeedsRoot     bool     `json:"needs_root"`
	}

	type moduleConfigJSON struct {
		Name         string          `json:"name"`
		Build        string          `json:"build"`
		Author       string          `json:"author"`
		Date         string          `json:"date"`
		Comment      string          `json:"comment"`
		IsLocal      bool            `json:"is_local"`
		Platform     string          `json:"platform"`
		Path         string          `json:"path"`
		Fileless     bool            `json:"fileless"`
		AgentConfig  agentConfigJSON `json:"agent_config"`
		Parameters   []optionJSON    `json:"parameters"`
		Invocation   invocationJSON  `json:"invocation"`
		Dependencies []string        `json:"dependencies"`
		// ModuleFilesMemFS uploads and caches all companion files in
		// encrypted memfs so multi-file starlark modules can read them via
		// read_file("memfs:///...").
		ModuleFilesMemFS bool `json:"module_files_memfs"`
	}

	jsonData, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("read %s: %v", file, err)
	}

	var rawList []moduleConfigJSON
	if err = json.Unmarshal(jsonData, &rawList); err != nil {
		var raw moduleConfigJSON
		if err = json.Unmarshal(jsonData, &raw); err != nil {
			return nil, fmt.Errorf("failed to unmarshal JSON config: %v", err)
		}
		rawList = []moduleConfigJSON{raw}
	}

	for _, raw := range rawList {
		config := def.ModuleConfig{
			Name:     raw.Name,
			Build:    raw.Build,
			Author:   raw.Author,
			Date:     raw.Date,
			Comment:  raw.Comment,
			IsLocal:  raw.IsLocal,
			Platform: raw.Platform,
			Path:     raw.Path,
			Fileless: raw.Fileless,
			Options:  def.ModOptions{},
			AgentConfig: def.AgentModuleConfig{
				Exec:          raw.AgentConfig.Exec,
				Files:         raw.AgentConfig.Files,
				InMemory:      raw.AgentConfig.InMemory,
				Type:          raw.AgentConfig.Type,
				IsInteractive: raw.AgentConfig.IsInteractive,
				WorkDir:       raw.AgentConfig.WorkDir,
				NeedsRoot:     raw.AgentConfig.NeedsRoot,
			},
			ModuleFilesMemFS: raw.ModuleFilesMemFS,
		}

		config.Invocation.TimeoutSeconds = raw.Invocation.TimeoutSeconds
		config.Invocation.StdinParam = raw.Invocation.StdinParam
		config.Invocation.CoffExport = raw.Invocation.CoffExport
		config.Invocation.DllExport = raw.Invocation.DllExport
		config.Invocation.DllEntry = raw.Invocation.DllEntry
		config.Invocation.DllFileParam = raw.Invocation.DllFileParam
		config.Dependencies = raw.Dependencies

		seenParams := make(map[string]bool)
		for _, p := range raw.Parameters {
			if p.Name == "" {
				continue
			}
			if seenParams[p.Name] {
				logging.Warningf("Module '%s' config warning: duplicate parameter '%s' defined", raw.Name, p.Name)
			}
			seenParams[p.Name] = true

			// Check for conflicts with reserved command-line flags
			if p.Name == "force" || p.Name == "help" {
				logging.Warningf("Module '%s' config warning: parameter '%s' conflicts with reserved command-line flags (Cobra/pflag built-in)", raw.Name, p.Name)
			}

			config.Options[p.Name] = &def.ModOption{
				Name:     p.Name,
				Desc:     p.Desc,
				Val:      p.Val,
				Vals:     p.Vals,
				Type:     p.Type,
				Required: p.Required,
				Pattern:  p.Pattern,
				Encoding: p.Encoding,
				Secret:   p.Secret,
				Min:      p.Min,
				Max:      p.Max,
				ArgvFlag: p.ArgvFlag,
			}
		}

		isCOFF := strings.EqualFold(raw.AgentConfig.Type, "coff")
		isDLL := strings.EqualFold(raw.AgentConfig.Type, "dll")

		// DLL defaults (in-memory DLL loader convention)
		if isDLL {
			if config.Invocation.DllExport == "" {
				config.Invocation.DllExport = "LoadAndRun"
			}
			if config.Invocation.DllEntry == "" {
				config.Invocation.DllEntry = "go"
			}
			if config.Invocation.DllFileParam == "" {
				config.Invocation.DllFileParam = "file"
			}
		}

		// Literal-only argv prefix entries
		for _, a := range raw.Invocation.Argv {
			config.Invocation.Argv = append(config.Invocation.Argv, def.InvocationArg{
				Literal: a.Literal,
				Flag:    a.Flag,
			})
		}

		// Derive argv entries from ordered parameters
		for _, p := range raw.Parameters {
			if p.Name == "" {
				continue
			}
			config.Invocation.Argv = append(config.Invocation.Argv, def.InvocationArg{
				Flag:  p.ArgvFlag,
				Param: p.Name,
			})
		}

		// Derive CoffInvocation from parameters.
		// COFF modules pack their exported entry (usually "go"). DLL loader
		// modules use DllEntry as the BOF entry name instead.
		coffExport := raw.Invocation.CoffExport
		if isDLL {
			coffExport = config.Invocation.DllEntry
		}
		if (isCOFF || isDLL) && coffExport != "" {
			coff := def.CoffInvocation{Export: coffExport}
			for _, p := range raw.Parameters {
				if p.Name == "" {
					continue
				}
				// The BOF file path is a control parameter for DLL modules,
				// not a BOF argument.
				if isDLL && config.Invocation.DllFileParam != "" && p.Name == config.Invocation.DllFileParam {
					continue
				}
				coff.Args = append(coff.Args, def.CoffArgSpec{
					Param:    p.Name,
					Encoding: p.Encoding,
				})
			}
			config.Invocation.Coff = &coff
		}

		// Windows BOF modules automatically depend on the in-memory COFFLoader DLL.
		if isCOFF && def.IsWindowsPlatform(raw.Platform) {
			found := false
			for _, dep := range config.Dependencies {
				if strings.EqualFold(dep, "coffloader") {
					found = true
					break
				}
			}
			if !found {
				config.Dependencies = append(config.Dependencies, "coffloader")
			}
		}

		configs = append(configs, &config)
	}

	return configs, nil
}

// typeToWireToken maps the unified parameter type to a COFFLoader wire token.
// Returns "" for non-COFF types (starlark, string, int, …); the caller should
// only pass COFF-relevant types.
//
// Wire token conventions follow the COFFLoader beacon_generate.py standard:
//
//	z      – UTF-8 C-string (addString)
//	Z      – UTF-16LE wide string (addWString)
//	i      – 32-bit integer (addint)
//	s      – 16-bit short integer (addshort)
//	b      – length-prefixed binary blob (base64 input)
func typeToWireToken(typeName string) string {
	// Canonical single-char tokens are case-sensitive: z is narrow, Z is wide,
	// s is short.
	switch typeName {
	case "z":
		return "z"
	case "Z":
		return "Z"
	case "i":
		return "i"
	case "s":
		return "s"
	case "b":
		return "b"
	}

	switch strings.ToLower(typeName) {
	case "cstr", "string", "str", "lpstr":
		return "z"
	case "wstr", "wstring", "lpwstr", "w":
		return "Z"
	case "int", "dword", "uint32", "uint", "int32", "port", "bool":
		return "i"
	case "short", "word", "int16":
		return "s"
	case "binary", "base64":
		return "b"
	default:
		return ""
	}
}

// coffArgNeedsZero reports whether a rendered COFF argument value must be
// replaced with a zero value: numeric wire types (i/s) reject an empty string
// when packed on the agent side.
func coffArgNeedsZero(typed any, wireTyp string) bool {
	if s, ok := typed.(string); ok && s == "" {
		return wireTyp == "i" || wireTyp == "s"
	}
	return false
}

// coffArgZeroValue returns a valid zero value for a COFF wire token so a
// declared BOF argument is always packed even when the operator left it empty.
func coffArgZeroValue(wireTyp string) any {
	switch wireTyp {
	case "i", "s":
		return float64(0)
	default:
		return ""
	}
}

// ResolveInvocation renders an invocation with concrete values from module options.
//
// For COFF modules the WireType on each ResolvedCoffArg is derived from the
// parameter's unified "type" field via typeToWireToken.
func ResolveInvocation(config *def.ModuleConfig, flags map[string]string) (def.ResolvedInvocation, error) {
	resolved := def.ResolvedInvocation{TimeoutSeconds: config.Invocation.TimeoutSeconds}

	// ── token (Windows impersonation) ─────────────────────────────────────
	// The "token" option is special: it is not passed as argv but wired
	// directly into ResolvedInvocation.Token for the agent's ExecuteAsToken.
	if tokenSID, ok := flags["token"]; ok {
		resolved.Token = strings.TrimSpace(tokenSID)
	}

	// ── --user netlogon session + Kerberos ticket (Windows) ────────────────
	// Injected options: --user creates/reuses a netlogon session for the user
	// and --ticket imports a KRB-CRED into the resolved session before the
	// module runs. Only wired when the option was injected (i.e. the module
	// did not declare its own "user"/"ticket" parameter).
	if def.OptionWasInjected(config.Name, "user") {
		if user, ok := flags["user"]; ok {
			resolved.SessionUser = strings.TrimSpace(user)
		}
	}
	if def.OptionWasInjected(config.Name, "ticket") {
		if ticket, ok := flags["ticket"]; ok {
			resolved.Ticket = strings.TrimSpace(ticket)
		}
	}

	// ── dependencies & DLL invocation ─────────────────────────────────────
	resolved.Dependencies = config.Dependencies
	resolved.DllExport = config.Invocation.DllExport
	resolved.DllEntry = config.Invocation.DllEntry

	lookupOpt := func(name string) (*def.ModOption, string, error) {
		if config.Options != nil {
			if opt, ok := config.Options[name]; ok && opt != nil {
				if val, ok := flags[name]; ok {
					return opt, val, nil
				}
				return opt, opt.Val, nil
			}
		}
		return nil, "", fmt.Errorf("option %s not defined", name)
	}

	coerceVal := func(name string) (string, any, error) {
		opt, val, err := lookupOpt(name)
		if err != nil {
			return "", nil, err
		}
		return renderOptionValue(opt, val)
	}

	// Starlark is dynamically typed: its main(*args) receives positional
	// strings and scripts coerce values themselves (int(), bool(), ...). BOF
	// arg packing (type validation, zero-filling, dropping empty args) must
	// not apply here, because dropping an empty optional arg would shift every
	// subsequent positional argument.
	isStarlark := strings.EqualFold(config.AgentConfig.Type, "starlark")
	rawVal := func(name string) (string, error) {
		opt, val, err := lookupOpt(name)
		if err != nil {
			return "", err
		}
		if strings.TrimSpace(val) == "" && opt.Required {
			return "", fmt.Errorf("option %s is required", opt.Name)
		}
		return val, nil
	}

	// ── argv ──────────────────────────────────────────────────────────────
	for _, arg := range config.Invocation.Argv {
		switch {
		case arg.Literal != "":
			resolved.Argv = append(resolved.Argv, arg.Literal)
		case arg.Flag != "" && arg.Param != "":
			var strVal string
			var err error
			if isStarlark {
				strVal, err = rawVal(arg.Param)
			} else {
				strVal, _, err = coerceVal(arg.Param)
			}
			if err != nil {
				return resolved, err
			}
			if !isStarlark && strVal == "" {
				continue
			}
			resolved.Argv = append(resolved.Argv, arg.Flag, strVal)
		case arg.Param != "":
			var strVal string
			var err error
			if isStarlark {
				strVal, err = rawVal(arg.Param)
			} else {
				strVal, _, err = coerceVal(arg.Param)
			}
			if err != nil {
				return resolved, err
			}
			if !isStarlark && strVal == "" {
				continue
			}
			resolved.Argv = append(resolved.Argv, strVal)
		}
	}

	// ── stdin ─────────────────────────────────────────────────────────────
	if config.Invocation.StdinParam != "" {
		stdinVal, _, err := coerceVal(config.Invocation.StdinParam)
		if err != nil {
			return resolved, err
		}
		resolved.Stdin = stdinVal
	}

	// ── COFF packing ─────────────────────────────────────────────────────
	// Wire type comes from the parameter's unified "type" field.
	// Every declared BOF argument is always packed, even when the operator
	// did not supply a value, so the BOF always receives a well-formed arg
	// list and never dereferences a NULL BeaconDataExtract result.
	if config.Invocation.Coff != nil {
		coffInv := &def.ResolvedCoffInvocation{Export: config.Invocation.Coff.Export}
		for _, arg := range config.Invocation.Coff.Args {
			opt, val, lookupErr := lookupOpt(arg.Param)
			if lookupErr != nil {
				return resolved, lookupErr
			}
			wireTyp := typeToWireToken(opt.Type)
			_, typed, renderErr := renderOptionValue(opt, val)
			if renderErr != nil || coffArgNeedsZero(typed, wireTyp) {
				logging.Warningf("BOF arg '%s' (%s) not supplied, packing zero value", arg.Param, wireTyp)
				typed = coffArgZeroValue(wireTyp)
			}
			coffInv.Args = append(coffInv.Args, def.ResolvedCoffArg{
				WireType: wireTyp,
				Value:    typed,
				Encoding: arg.Encoding,
			})
		}
		resolved.Coff = coffInv
	}

	// ── DLL file parameter ────────────────────────────────────────────────
	// The named parameter points at the BOF object file on the agent
	// (memfs:/// or disk). It is resolved here but not packed as a BOF arg.
	if config.Invocation.DllFileParam != "" {
		fileVal, _, err := coerceVal(config.Invocation.DllFileParam)
		if err != nil {
			return resolved, err
		}
		resolved.DllFileValue = fileVal
	}

	return resolved, nil
}

// renderOptionValue validates and returns both string and typed representations.
// The unified "type" field covers both non-COFF validation types (string, int,
// uint, bool, port, base64) and COFF wire types (cstr, wstr, dword, short,
// binary).  COFF-specific types fall through to the nearest generic equivalent.
func renderOptionValue(opt *def.ModOption, val string) (string, any, error) {
	val = strings.TrimSpace(val)
	if val == "" {
		if opt.Required {
			return "", nil, fmt.Errorf("option %s is required", opt.Name)
		}
		return "", "", nil
	}

	if len(opt.Vals) > 0 {
		found := false
		for _, v := range opt.Vals {
			if v == val {
				found = true
				break
			}
		}
		if !found {
			return "", nil, fmt.Errorf("option %s must be one of %v", opt.Name, opt.Vals)
		}
	}

	switch strings.ToLower(opt.Type) {
	// ── Boolean ────────────────────────────────────────────────────────
	case "bool":
		b, err := strconv.ParseBool(val)
		if err != nil {
			return "", nil, fmt.Errorf("option %s expects bool: %w", opt.Name, err)
		}
		return strconv.FormatBool(b), b, nil

	// ── Signed / unsigned integers ─────────────────────────────────────
	// Generic:        int, uint, port
	// COFF aliases:   dword/i/uint32/int32, short/word/int16
	case "int", "dword", "i", "uint32", "int32":
		num, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return "", nil, fmt.Errorf("option %s expects int: %w", opt.Name, err)
		}
		if opt.Min != nil && float64(num) < *opt.Min {
			return "", nil, fmt.Errorf("option %s below min", opt.Name)
		}
		if opt.Max != nil && float64(num) > *opt.Max {
			return "", nil, fmt.Errorf("option %s above max", opt.Name)
		}
		return fmt.Sprintf("%d", num), float64(num), nil

	case "uint", "port":
		num, err := strconv.ParseUint(val, 10, 64)
		if err != nil {
			return "", nil, fmt.Errorf("option %s expects uint: %w", opt.Name, err)
		}
		if opt.Min != nil && float64(num) < *opt.Min {
			return "", nil, fmt.Errorf("option %s below min", opt.Name)
		}
		if opt.Max != nil && float64(num) > *opt.Max {
			return "", nil, fmt.Errorf("option %s above max", opt.Name)
		}
		return fmt.Sprintf("%d", num), float64(num), nil

	case "short", "word", "int16":
		num, err := strconv.ParseInt(val, 10, 16)
		if err != nil {
			return "", nil, fmt.Errorf("option %s expects int16: %w", opt.Name, err)
		}
		return fmt.Sprintf("%d", num), float64(num), nil

	// ── String variants ────────────────────────────────────────────────
	// Generic:       string
	// COFF aliases:  cstr/s/lpstr (UTF-8), wstr/w/lpwstr (UTF-16LE)
	// Both are treated as plain Go strings on the C2 side; the agent's
	// coffloader handles the actual encoding difference.
	case "string", "cstr", "s", "lpstr", "wstr", "w", "lpwstr", "wstring":
		return val, val, nil

	// ── Binary / base64 ───────────────────────────────────────────────
	// Accepted as-is (base64 string); agent unpacks.
	case "binary", "b", "base64":
		return val, val, nil

	default:
		return val, val, nil
	}
}

// CoffArgsFromResolved converts a resolved COFF invocation into the
// coffloader representation consumed by the in-memory loader. It never
// mutates the input.
func CoffArgsFromResolved(coff *def.ResolvedCoffInvocation) []coffloader.CoffArg {
	if coff == nil {
		return nil
	}
	args := make([]coffloader.CoffArg, 0, len(coff.Args))
	for _, a := range coff.Args {
		args = append(args, coffloader.CoffArg{WireType: a.WireType, Value: a.Value})
	}
	return args
}

// ResolveCoffArgs resolves operator-supplied flag values against a COFF
// module's declared parameters and returns the packed-argument list ready
// for the COFFLoader. It is a convenience wrapper around ResolveInvocation
// for callers that only care about the BOF arguments.
func ResolveCoffArgs(config *def.ModuleConfig, flags map[string]string) ([]coffloader.CoffArg, error) {
	if config == nil {
		return nil, fmt.Errorf("nil module config")
	}
	invocation, err := ResolveInvocation(config, flags)
	if err != nil {
		return nil, err
	}
	if invocation.Coff == nil {
		return nil, fmt.Errorf("module %q has no COFF invocation", config.Name)
	}
	return CoffArgsFromResolved(invocation.Coff), nil
}

// FindConfigFile locates the config.json that describes the module a BOF
// belongs to. It checks the BOF's own directory and its parent, which covers
// both the flat layout (<module>/config.json + <module>/x.o) and the usual
// suite layout (<module>/config.json + <module>/_bin/x.o).
func FindConfigFile(bofPath string) (string, error) {
	dir := filepath.Dir(bofPath)
	candidates := []string{
		filepath.Join(dir, "config.json"),
		filepath.Join(dir, "..", "config.json"),
	}
	for _, candidate := range candidates {
		if fi, err := os.Stat(candidate); err == nil && !fi.IsDir() {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("no config.json found next to %s", bofPath)
}

// SelectModule picks one module from a parsed config.json. When name is
// non-empty it must match a module name exactly. Otherwise payloadName (the
// BOF basename) is matched against every module's agent_config.files, which
// disambiguates suites that share a single manifest. A manifest declaring a
// single module is returned without further matching.
func SelectModule(configs []*def.ModuleConfig, name, payloadName string) (*def.ModuleConfig, error) {
	if len(configs) == 0 {
		return nil, fmt.Errorf("config declares no modules")
	}

	if name != "" {
		for _, config := range configs {
			if config != nil && config.Name == name {
				return config, nil
			}
		}
		return nil, fmt.Errorf("module %q not found in config", name)
	}

	if payloadName != "" {
		base := filepath.Base(payloadName)
		var matches []*def.ModuleConfig
		for _, config := range configs {
			if config == nil {
				continue
			}
			for _, file := range config.AgentConfig.Files {
				if strings.EqualFold(filepath.Base(file), base) {
					matches = append(matches, config)
					break
				}
			}
		}
		switch len(matches) {
		case 1:
			return matches[0], nil
		case 0:
			// No payload match: fall back to the single-module case below.
		default:
			names := make([]string, 0, len(matches))
			for _, match := range matches {
				names = append(names, match.Name)
			}
			return nil, fmt.Errorf("payload %s matches multiple modules %v; pass -module", base, names)
		}
	}

	if len(configs) == 1 {
		return configs[0], nil
	}
	return nil, fmt.Errorf("config declares %d modules; pass -module to pick one", len(configs))
}
