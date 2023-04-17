package agent

import (
	"log"
	"os"
	"runtime"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// SetPath get current PATH variable and append it with common paths, then remove duplicates
func SetPath() {
	common_paths := []string{}
	current_paths := os.Getenv("PATH")
	path_delimiter := ":"
	if runtime.GOOS == "windows" {
		common_paths = []string{
			`c:\windows\system32`,
			`c:\windows`,
			`c:\windows\system32\wbem`,
			`c:\windows\system32\windowspowershell\v1.0`,
			`c:\windows\system32\openssh`,
		}
		path_delimiter = ";"
		temp := []string{}
		for _, path := range strings.Split(current_paths, path_delimiter) {
			temp = append(temp,
				strings.Trim(strings.ToLower(path), "\\"))
		}
		current_paths = strings.Join(temp, path_delimiter)

	} else if runtime.GOOS == "linux" {
		common_paths = []string{
			"/bin",
			"/sbin",
			"/usr/bin",
			"/usr/games",
			"/usr/sbin",
			"/usr/local/bin",
			"/usr/local/sbin",
			"/snap/bin",
		}
		temp := []string{}
		for _, path := range strings.Split(current_paths, path_delimiter) {
			temp = append(temp,
				strings.Trim(path, "/"))
		}
		current_paths = strings.Join(temp, path_delimiter)
	}
	current_paths_array := strings.Split(current_paths, path_delimiter)
	paths := append(current_paths_array, common_paths...)
	paths = util.RemoveDupsFromArray(paths)
	if runtime.GOOS == "linux" {
		paths = append([]string{RuntimeConfig.UtilsPath}, paths...)
	}
	path_str := strings.Join(paths, path_delimiter)
	if runtime.GOOS == "windows" {
		path_str += path_delimiter
	}

	os.Setenv("PATH", path_str)
	log.Printf("PATH=%s", path_str)
}
