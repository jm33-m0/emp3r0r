package agent

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/gliderlabs/ssh"
)

// SSHD start a ssh server to provide shell access for clients
// the server binds local interface only
func crossPlatformSSHD(shell, port string, args []string) (err error) {
	if strings.HasSuffix(shell, "bash") {
		shell = "cmd.exe"
	} else {
		exe, e := exec.LookPath(shell)
		if err != nil {
			err = fmt.Errorf("%s not found (%v)", shell, e)
			log.Print(err)
			return
		}
		shell = exe
	}
	log.Printf("Using %s shell", strconv.Quote(shell))
	args = append([]string{shell}, args...)

	ssh.Handle(func(s ssh.Session) {
		cmd := exec.Command("conhost.exe", args...) // shell command
		cmd.Env = os.Environ()
		cmd.Stderr = s.Stderr()
		cmd.Stdin = s
		cmd.Stdout = s
		err = cmd.Start()
		if err != nil {
			log.Printf("Start shell %s: %v", shell, err)
			return
		}
		err = cmd.Wait()
		if err != nil {
			log.Printf("Wait shell %s: %v", shell, err)
			return
		}
	})

	log.Printf("Starting SSHD on port %s...", port)
	return ssh.ListenAndServe("127.0.0.1:"+port, nil)
}
