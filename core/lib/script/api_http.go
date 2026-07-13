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
	resp, err := http.Get(url)
	if err != nil {
		return starlark.None, fmt.Errorf("http_get %s: %w", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return starlark.None, fmt.Errorf("http_get %s: reading body: %w", url, err)
	}
	return starlark.String(body), nil
}

func starlarkHTTPPost(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var url string
	var contentType string
	var bodyData string
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "url", &url, "content_type", &contentType, "body", &bodyData); err != nil {
		return starlark.None, err
	}
	resp, err := http.Post(url, contentType, strings.NewReader(bodyData))
	if err != nil {
		return starlark.None, fmt.Errorf("http_post %s: %w", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return starlark.None, fmt.Errorf("http_post %s: reading body: %w", url, err)
	}
	return starlark.String(body), nil
}
