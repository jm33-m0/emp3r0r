package tools

import (
	"github.com/cavaliergopher/grab/v3"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// DownloadFile download file using default http client
func DownloadFile(url, path string) (err error) {
	logging.Debugf("Downloading '%s' to '%s'", url, path)
	_, err = grab.Get(path, url)
	return
}
