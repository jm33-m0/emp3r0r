package agentw

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"

	"github.com/gliderlabs/ssh"
)

// SSHD start a ssh server to provide shell access for clients
// the server binds local interface only
func SSHD(shell, port string, args []string) (err error) {
	exe, e := exec.LookPath(shell)
	if err != nil {
		err = fmt.Errorf("%s not found (%v)", shell, e)
		log.Print(err)
	}
	shell = exe
	log.Printf("Using %s shell", strconv.Quote(shell))

	ssh.Handle(func(s ssh.Session) {
		cmd := exec.Command(shell, args...) // shell command
		cmd.Env = append(cmd.Env, os.Environ()...)
		// cmd.Env = append(cmd.Env, "TERM=xterm")
		cmd.Stderr = s
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
