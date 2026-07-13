//go:build !windows

package script

import (
	"os"
	"strconv"
	"strings"
	"time"

	"go.starlark.net/starlark"
)

var startTime = time.Now()

func starlarkGetTickCount64(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	// Try reading /proc/uptime on Linux
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) > 0 {
			if seconds, err := strconv.ParseFloat(fields[0], 64); err == nil {
				return starlark.MakeInt64(int64(seconds * 1000)), nil
			}
		}
	}
	// Fallback: ticks since process start
	return starlark.MakeInt64(time.Since(startTime).Milliseconds()), nil
}

func starlarkGetLocalTime(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	now := time.Now()
	res := starlark.NewDict(6)
	res.SetKey(starlark.String("year"), starlark.MakeInt(now.Year()))
	res.SetKey(starlark.String("month"), starlark.MakeInt(int(now.Month())))
	res.SetKey(starlark.String("day"), starlark.MakeInt(now.Day()))
	res.SetKey(starlark.String("hour"), starlark.MakeInt(now.Hour()))
	res.SetKey(starlark.String("minute"), starlark.MakeInt(now.Minute()))
	res.SetKey(starlark.String("second"), starlark.MakeInt(now.Second()))
	return res, nil
}

func starlarkGetSystemDefaultLocaleName(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	lang := os.Getenv("LANG")
	if lang == "" {
		return starlark.String("en-US"), nil
	}
	// e.g., en_US.UTF-8 -> en-US
	parts := strings.Split(lang, ".")
	loc := strings.ReplaceAll(parts[0], "_", "-")
	return starlark.String(loc), nil
}

func starlarkGetLocaleInfoEx(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var localeName string
	var lcType int
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "locale_name", &localeName, "lc_type", &lcType); err != nil {
		return starlark.None, err
	}

	// Mocking values based on LCType constants
	// LOCALE_SENGLANGUAGE = 0x00001001
	// LOCALE_SLOCALIZEDCOUNTRYNAME = 0x00000006
	switch lcType {
	case 0x1001:
		return starlark.String("English"), nil
	case 0x6:
		return starlark.String("United States"), nil
	default:
		return starlark.String("Unknown"), nil
	}
}

func starlarkLocaleNameToLCID(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var localeName string
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "locale_name", &localeName); err != nil {
		return starlark.None, err
	}
	// Return English (US) LCID: 0x0409 (1033)
	return starlark.MakeInt(1033), nil
}

func starlarkGetDateFormatEx(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var localeName string
	var dwFlags int
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "locale_name", &localeName, "dw_flags", &dwFlags); err != nil {
		return starlark.None, err
	}
	// Long date format: e.g. "Monday, July 13, 2026"
	return starlark.String(time.Now().Format("Monday, January 2, 2006")), nil
}

func starlarkGetEnvironmentStrings(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	envList := starlark.NewList(nil)
	for _, env := range os.Environ() {
		envList.Append(starlark.String(env))
	}
	return envList, nil
}
