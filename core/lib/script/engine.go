package script

import (
	"bytes"
	"fmt"

	"go.starlark.net/starlark"
	"go.starlark.net/syntax"
)

// Run executes a Starlark script with the provided source code, arguments, and optional custom global variables.
// It redirects all Starlark print() calls to a string buffer and returns the captured output along with any execution error.
func Run(src []byte, argv []string, customGlobals map[string]any) (string, error) {
	var buf bytes.Buffer

	// Create a new Starlark thread
	thread := &starlark.Thread{
		Name: "script_engine_thread",
		Print: func(thread *starlark.Thread, msg string) {
			buf.WriteString(msg)
			buf.WriteString("\n")
		},
	}

	// Fetch built-in APIs
	predeclared := getAPIs()

	// Predeclare argv as a global list of strings
	argvList := starlark.NewList(nil)
	for _, arg := range argv {
		argvList.Append(starlark.String(arg))
	}
	predeclared["argv"] = argvList

	// Load custom globals if any
	for k, v := range customGlobals {
		if val, err := convertToStarlarkValue(v); err == nil {
			predeclared[k] = val
		}
	}

	// Execute Starlark script from memory
	globals, err := starlark.ExecFileOptions(&syntax.FileOptions{
		TopLevelControl: true,
		Recursion:       true,
		GlobalReassign:  true,
		While:           true,
	}, thread, "script.star", src, predeclared)
	if err != nil {
		return buf.String(), fmt.Errorf("starlark execution: %w", err)
	}

	// If main function is defined in the script, call it with arguments
	if mainVal, ok := globals["main"]; ok {
		if mainFn, ok := mainVal.(starlark.Callable); ok {
			starArgs := make(starlark.Tuple, 0, len(argv))
			for _, arg := range argv {
				starArgs = append(starArgs, starlark.String(arg))
			}
			resVal, err := starlark.Call(thread, mainFn, starArgs, nil)
			if err != nil {
				return buf.String(), fmt.Errorf("calling main function: %w", err)
			}
			if resVal != starlark.None {
				buf.WriteString(resVal.String())
				buf.WriteString("\n")
			}
		}
	}

	return buf.String(), nil
}

// convertToStarlarkValue maps simple Go types to their Starlark representations
func convertToStarlarkValue(v any) (starlark.Value, error) {
	switch val := v.(type) {
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
	case float64:
		return starlark.Float(val), nil
	case []string:
		list := starlark.NewList(nil)
		for _, s := range val {
			list.Append(starlark.String(s))
		}
		return list, nil
	default:
		return starlark.None, fmt.Errorf("unsupported type for starlark conversion: %T", v)
	}
}
