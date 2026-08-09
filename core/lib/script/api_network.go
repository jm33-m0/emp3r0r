package script

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"go.starlark.net/starlark"
)

func starlarkHTTPGet(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var url string
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "url", &url); err != nil {
		return starlark.None, err
	}
	var body []byte
	err := runWithToken(thread, func() error {
		resp, e := http.Get(url)
		if e != nil {
			return fmt.Errorf("http_get %s: %w", url, e)
		}
		defer resp.Body.Close()
		body, e = io.ReadAll(resp.Body)
		if e != nil {
			return fmt.Errorf("http_get %s: reading body: %w", url, e)
		}
		return nil
	})
	if err != nil {
		return starlark.None, err
	}
	return starlark.String(string(body)), nil
}

func starlarkHTTPPost(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var url string
	var contentType string
	var bodyData string
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "url", &url, "content_type", &contentType, "body", &bodyData); err != nil {
		return starlark.None, err
	}
	var body []byte
	err := runWithToken(thread, func() error {
		resp, e := http.Post(url, contentType, strings.NewReader(bodyData))
		if e != nil {
			return fmt.Errorf("http_post %s: %w", url, e)
		}
		defer resp.Body.Close()
		body, e = io.ReadAll(resp.Body)
		if e != nil {
			return fmt.Errorf("http_post %s: reading body: %w", url, e)
		}
		return nil
	})
	if err != nil {
		return starlark.None, err
	}
	return starlark.String(string(body)), nil
}
