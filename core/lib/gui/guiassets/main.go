// Command guiassets downloads the third-party browser assets (xterm.js and
// the xterm fit addon, both MIT licensed) that the emp3r0r operator GUI
// embeds into the cc binary at build time.
//
// The JS/CSS are not kept in the git tree (see .gitignore,
// core/lib/gui/gui/assets/). Instead they are fetched, verified
// and cached right before the cc binary is compiled by either:
//
//	go generate ./internal/cc/operator          (developer flow)
//	core/build.py                                (canonical build, runs it too)
//
// Every file is content-addressed: if a file already exists with the pinned
// SHA-256 it is left untouched, so repeated builds are no-ops and offline
// rebuilds reuse the previously downloaded copy.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// asset pins one file to a URL and an expected SHA-256. Bump the version in
// the URL and update the hash whenever the assets are upgraded.
type asset struct {
	name string
	url  string
	sha  string
}

var assets = []asset{
	{
		name: "xterm.js",
		url:  "https://unpkg.com/xterm@5.3.0/lib/xterm.js",
		sha:  "f0aea0f75f48559013ae6643c2479dd737d26da42d5524e6d2b70915ae6523c7",
	},
	{
		name: "xterm.css",
		url:  "https://unpkg.com/xterm@5.3.0/css/xterm.css",
		sha:  "832f3f2c603b43ad4351ff04970150cc7a873014276db126a6065c6dd81e4872",
	},
	{
		name: "xterm-addon-fit.js",
		url:  "https://unpkg.com/@xterm/addon-fit@0.10.0/lib/addon-fit.js",
		sha:  "bdaefa370b1bfc42ee88d46fe6072400902a4d4b2d45cd93438dda9b23c97089",
	},
	{
		name: "xterm-LICENSE.txt",
		url:  "https://raw.githubusercontent.com/xtermjs/xterm.js/5.3.0/LICENSE",
		sha:  "b569f629d00f2626a8100df2a1798210535621e42164dfd426a6fe5aac7b0ccd",
	},
}

func main() {
	// Anchor the output directory to this source file so the tool works no
	// matter what the current working directory is (go:generate and build.py
	// invoke it from different directories).
	_, srcFile, _, ok := runtime.Caller(0)
	if !ok {
		fmt.Fprintln(os.Stderr, "guiassets: cannot locate source directory")
		os.Exit(1)
	}
	assetsDir := filepath.Join(filepath.Dir(srcFile), "..", "gui", "assets")
	if err := os.MkdirAll(assetsDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "guiassets: mkdir %s: %v\n", assetsDir, err)
		os.Exit(1)
	}

	client := &http.Client{Timeout: 60 * time.Second}
	for _, a := range assets {
		dst := filepath.Join(assetsDir, a.name)
		if sum, err := fileSHA256(dst); err == nil && sum == a.sha {
			fmt.Printf("guiassets: %s up to date\n", a.name)
			continue
		}
		if err := fetch(client, a, dst); err != nil {
			fmt.Fprintf(os.Stderr, "guiassets: %v\n", err)
			os.Exit(1)
		}
	}
	fmt.Printf("guiassets: assets ready in %s\n", assetsDir)
}

// fetch downloads one asset to dst, verifies its SHA-256 and atomically
// renames it into place.
func fetch(client *http.Client, a asset, dst string) error {
	fmt.Printf("guiassets: downloading %s -> %s\n", a.url, a.name)
	req, err := http.NewRequest(http.MethodGet, a.url, nil)
	if err != nil {
		return fmt.Errorf("request %s: %w", a.url, err)
	}
	req.Header.Set("User-Agent", "emp3r0r-guiassets")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download %s: %w", a.url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: HTTP %s", a.url, resp.Status)
	}

	tmp := dst + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("create %s: %w", tmp, err)
	}
	hasher := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, hasher), resp.Body); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("close %s: %w", tmp, err)
	}
	if got := hex.EncodeToString(hasher.Sum(nil)); got != a.sha {
		os.Remove(tmp)
		return fmt.Errorf("checksum mismatch for %s: got %s, want %s", a.name, got, a.sha)
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename %s: %w", tmp, err)
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
