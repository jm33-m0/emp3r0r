package script

import (
	"fmt"
	"strings"

	"go.starlark.net/starlark"
)

// starlarkStrSplit splits string s by separator sep
func starlarkStrSplit(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var s, sep string
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "s", &s, "sep", &sep); err != nil {
		return starlark.None, err
	}
	parts := strings.Split(s, sep)
	elems := make([]starlark.Value, len(parts))
	for i, p := range parts {
		elems[i] = starlark.String(p)
	}
	return starlark.NewList(elems), nil
}

// starlarkStrJoin joins a list of strings with a separator string
func starlarkStrJoin(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var listVal starlark.Value
	var sep string
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "elements", &listVal, "sep", &sep); err != nil {
		return starlark.None, err
	}
	iter := starlark.Iterate(listVal)
	if iter == nil {
		return starlark.None, fmt.Errorf("elements parameter must be an iterable list or tuple")
	}
	defer iter.Done()

	var strParts []string
	var val starlark.Value
	for iter.Next(&val) {
		if str, ok := starlark.AsString(val); ok {
			strParts = append(strParts, str)
		} else {
			strParts = append(strParts, val.String())
		}
	}
	return starlark.String(strings.Join(strParts, sep)), nil
}

// starlarkStrReplace replaces occurrences of old substring with new substring in s
func starlarkStrReplace(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var s, old, newStr string
	n := -1
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "s", &s, "old", &old, "new", &newStr, "n?", &n); err != nil {
		return starlark.None, err
	}
	return starlark.String(strings.Replace(s, old, newStr, n)), nil
}

// starlarkStrContains checks if string s contains substring substr
func starlarkStrContains(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var s, substr string
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "s", &s, "substr", &substr); err != nil {
		return starlark.None, err
	}
	return starlark.Bool(strings.Contains(s, substr)), nil
}

// starlarkStrTrim trims leading/trailing whitespace or characters in cutset from s
func starlarkStrTrim(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var s string
	cutset := ""
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "s", &s, "cutset?", &cutset); err != nil {
		return starlark.None, err
	}
	if cutset == "" {
		return starlark.String(strings.TrimSpace(s)), nil
	}
	return starlark.String(strings.Trim(s, cutset)), nil
}

// starlarkStrLower converts s to lowercase
func starlarkStrLower(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var s string
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "s", &s); err != nil {
		return starlark.None, err
	}
	return starlark.String(strings.ToLower(s)), nil
}

// starlarkStrUpper converts s to uppercase
func starlarkStrUpper(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var s string
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "s", &s); err != nil {
		return starlark.None, err
	}
	return starlark.String(strings.ToUpper(s)), nil
}

// starlarkStrStartsWith checks if s has prefix
func starlarkStrStartsWith(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var s, prefix string
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "s", &s, "prefix", &prefix); err != nil {
		return starlark.None, err
	}
	return starlark.Bool(strings.HasPrefix(s, prefix)), nil
}

// starlarkStrEndsWith checks if s has suffix
func starlarkStrEndsWith(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var s, suffix string
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "s", &s, "suffix", &suffix); err != nil {
		return starlark.None, err
	}
	return starlark.Bool(strings.HasSuffix(s, suffix)), nil
}

// starlarkStrPad pads a string to specified width (right padded if width > 0, left padded if width < 0)
func starlarkStrPad(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var textVal starlark.Value
	var width int
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "text", &textVal, "width", &width); err != nil {
		return starlark.None, err
	}
	text, ok := starlark.AsString(textVal)
	if !ok {
		text = textVal.String()
	}

	leftAlign := true
	if width < 0 {
		leftAlign = false
		width = -width
	}

	if len(text) >= width {
		return starlark.String(text), nil
	}

	padding := strings.Repeat(" ", width-len(text))
	if leftAlign {
		return starlark.String(text + padding), nil
	}
	return starlark.String(padding + text), nil
}

// starlarkStrIndex returns the index of substr in s or -1
func starlarkStrIndex(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var s, substr string
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "s", &s, "substr", &substr); err != nil {
		return starlark.None, err
	}
	return starlark.MakeInt(strings.Index(s, substr)), nil
}
