package ssh

import (
	"io"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"

	"github.com/gliderlabs/ssh"
	"github.com/pkg/sftp"
)

// SftpHandler handler for SFTP subsystem
func SftpHandler(sess ssh.Session) {
	debugStream := io.Discard
	serverOptions := []sftp.ServerOption{
		sftp.WithDebug(debugStream),
	}
	server, err := sftp.NewServer(
		sess,
		serverOptions...,
	)
	if err != nil {
		logging.Errorf("sftp server init error: %s", err)
		return
	}
	if err := server.Serve(); err == io.EOF {
		server.Close()
		logging.Infof("sftp client exited session")
	} else if err != nil {
		logging.Errorf("sftp server completed with error: %v", err)
	}
}
