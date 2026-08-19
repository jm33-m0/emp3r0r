rule TCG_7eee7002 {
	meta:
		date = "2026-03-05"
		arch_context = "x64"
		scan_context = "file, memory"
		os = "windows"
		generator = "Crystal Palace"
	strings:
		// ----------------------------------------
		// Function: cleanup_memory
		// ----------------------------------------
		/*
		 * 48 89 D7                      mov rdi, rdx
		 * F3 48 AB                      rep stosq
		 * C7 45 00 1F 00 10 00          mov dword ptr [rbp], 0x10001F
		 * 48 8B 05 00 00 00 00          mov rax, qword ptr [__imp_KERNEL32$CreateTimerQueue]
		 * (Score: 137)
		 */
		$r0_cleanup_memory = { 48 89 D7 F3 48 AB C7 45 00 1F 00 10 00 48 8B 05 ?? ?? ?? ?? }

		/*
		 * 41 B8 70 0E 00 00             mov r8d, 0xE70
		 * BA 08 00 00 00                mov edx, 8
		 * 48 89 C1                      mov rcx, rax
		 * (Score: 42)
		 */
		$r1_cleanup_memory = { 41 B8 70 0E 00 00 BA 08 00 00 00 48 89 C1 }

		// ----------------------------------------
		// Function: get_text_section_size
		// ----------------------------------------
		/*
		 * 48 89 C1                      mov rcx, rax
		 * E8 87 F5 FF FF                call ror13hash
		 * 89 45 DC                      mov dword ptr [rbp-0x24], eax
		 * 81 7D DC B4 F9 C2 EB          cmp dword ptr [rbp-0x24], 0xEBC2F9B4
		 * (Score: 135)
		 */
		$r2_get_text_section_size = { 48 89 C1 E8 ?? ?? ?? ?? 89 45 DC 81 7D DC B4 F9 C2 EB }

		// ----------------------------------------
		// Function: _HeapFree
		// ----------------------------------------
		/*
		 * 48 8B 52 08                   mov rdx, qword ptr [rdx+8]
		 * 49 89 44 08 08                mov qword ptr [r8+rcx+8], rax
		 * 49 89 54 08 10                mov qword ptr [r8+rcx+0x10], rdx
		 * (Score: 128)
		 */
		$r3_HeapFree = { 48 8B 52 08 49 89 44 08 08 49 89 54 08 10 }

		// ----------------------------------------
		// Function: bypass_cfg
		// ----------------------------------------
		/*
		 * 48 8B 05 00 00 00 00          mov rax, qword ptr [__imp_NTDLL$NtSetInformationVirtualMemory]
		 * FF D0                         call rax
		 * 89 45 FC                      mov dword ptr [rbp-4], eax
		 * 81 7D FC F4 00 00 C0          cmp dword ptr [rbp-4], 0xC00000F4
		 * (Score: 134)
		 */
		$r4_bypass_cfg = { 48 8B 05 ?? ?? ?? ?? FF D0 89 45 FC 81 7D FC F4 00 00 C0 }

		// ----------------------------------------
		// Function: PicoLoad
		// ----------------------------------------
		/*
		 * 8B 52 08                      mov edx, dword ptr [rdx+8]
		 * 48 63 CA                      movsxd rcx, edx
		 * 48 8B 55 A8                   mov rdx, qword ptr [rbp-0x58]
		 * 8B 52 04                      mov edx, dword ptr [rdx+4]
		 * 48 63 D2                      movsxd rdx, edx
		 * (Score: 74)
		 */
		$r5_PicoLoad = { 8B 52 08 48 63 CA 48 8B 55 A8 8B 52 04 48 63 D2 }

		// ----------------------------------------
		// Function: _GetProcAddress
		// ----------------------------------------
		/*
		 * 48 89 C1                      mov rcx, rax
		 * E8 01 CB FF FF                call ror13hash
		 * 89 C1                         mov ecx, eax
		 * BA FB 97 FD 0F                mov edx, 0xFFD97FB
		 * 39 D1                         cmp ecx, edx
		 * (Score: 268)
		 */
		$r6_GetProcAddress = { 48 89 C1 E8 ?? ?? ?? ?? 89 C1 BA FB 97 FD 0F 39 D1 }

		// ----------------------------------------
		// Function: ProcessImport
		// ----------------------------------------
		/*
		 * 8B 52 0C                      mov edx, dword ptr [rdx+0xC]
		 * 89 D1                         mov ecx, edx
		 * 48 8B 55 20                   mov rdx, qword ptr [rbp+0x20]
		 * 48 01 CA                      add rdx, rcx
		 * 48 89 D1                      mov rcx, rdx
		 * (Score: 46)
		 */
		$r7_ProcessImport = { 8B 52 0C 89 D1 48 8B 55 20 48 01 CA 48 89 D1 }

		// ----------------------------------------
		// Function: adler32sum
		// ----------------------------------------
		/*
		 * 0F B6 D0                      movzx edx, al
		 * 8B 45 FC                      mov eax, dword ptr [rbp-4]
		 * 01 C2                         add edx, eax
		 * 89 D1                         mov ecx, edx
		 * B8 71 80 07 80                mov eax, 0x80078071
		 * (Score: 139)
		 */
		$r8_adler32sum = { 0F B6 D0 8B 45 FC 01 C2 89 D1 B8 71 80 07 80 }

		// ----------------------------------------
		// Function: dprintf
		// ----------------------------------------
		/*
		 * 41 B9 04 00 00 00             mov r9d, 4
		 * 41 B8 00 30 00 00             mov r8d, 0x3000
		 * 48 89 C2                      mov rdx, rax
		 * (Score: 42)
		 */
		$r9_dprintf = { 41 B9 04 00 00 00 41 B8 00 30 00 00 48 89 C2 }

	condition:
		5 of them
}

rule TCG_31614b2a {
	meta:
		date = "2026-03-05"
		arch_context = "x64"
		scan_context = "file, memory"
		os = "windows"
		generator = "Crystal Palace"
	strings:
		// ----------------------------------------
		// Function: go
		// ----------------------------------------
		/*
		 * 48 83 EC 20                   sub rsp, 0x20
		 * B9 5B BC 4A 6A                mov ecx, 0x6A4ABC5B
		 * BA AA FC 0D 7C                mov edx, 0x7C0DFCAA
		 * E8 17 07 00 00                call resolve
		 * (Score: 520)
		 */
		$r0_go = { 48 83 EC 20 B9 5B BC 4A 6A BA AA FC 0D 7C E8 ?? ?? ?? ?? }

		/*
		 * E8 2E 0F 00 00                call SizeOfDLL
		 * 89 C0                         mov eax, eax
		 * 41 B9 04 00 00 00             mov r9d, 4
		 * 41 B8 00 30 10 00             mov r8d, 0x103000
		 * (Score: 269)
		 */
		$r1_go = { E8 ?? ?? ?? ?? 89 C0 41 B9 04 00 00 00 41 B8 00 30 10 00 }

		// ----------------------------------------
		// Function: find_gadget
		// ----------------------------------------
		/*
		 * 48 83 EC 20                   sub rsp, 0x20
		 * B9 5D 68 FA 3C                mov ecx, 0x3CFA685D
		 * BA 44 06 B6 CD                mov edx, 0xCDB60644
		 * E8 30 02 00 00                call resolve
		 * (Score: 520)
		 */
		$r2_find_gadget = { 48 83 EC 20 B9 5D 68 FA 3C BA 44 06 B6 CD E8 ?? ?? ?? ?? }

		// ----------------------------------------
		// Function: _VirtualProtect
		// ----------------------------------------
		/*
		 * 48 83 EC 20                   sub rsp, 0x20
		 * B9 5B BC 4A 6A                mov ecx, 0x6A4ABC5B
		 * BA 1B C6 46 79                mov edx, 0x7946C61B
		 * E8 A8 01 00 00                call resolve
		 * (Score: 520)
		 */
		$r3_VirtualProtect = { 48 83 EC 20 B9 5B BC 4A 6A BA 1B C6 46 79 E8 ?? ?? ?? ?? }

		// ----------------------------------------
		// Function: get_text_section_size
		// ----------------------------------------
		/*
		 * 48 89 C1                      mov rcx, rax
		 * E8 EE FC FF FF                call ror13hash
		 * 89 45 DC                      mov dword ptr [rbp-0x24], eax
		 * 81 7D DC B4 F9 C2 EB          cmp dword ptr [rbp-0x24], 0xEBC2F9B4
		 * (Score: 135)
		 */
		$r4_get_text_section_size = { 48 89 C1 E8 ?? ?? ?? ?? 89 45 DC 81 7D DC B4 F9 C2 EB }

		// ----------------------------------------
		// Function: _VirtualFree
		// ----------------------------------------
		/*
		 * 48 83 EC 20                   sub rsp, 0x20
		 * B9 5B BC 4A 6A                mov ecx, 0x6A4ABC5B
		 * BA AC 33 06 03                mov edx, 0x30633AC
		 * E8 AE FE FF FF                call resolve
		 * (Score: 520)
		 */
		$r5_VirtualFree = { 48 83 EC 20 B9 5B BC 4A 6A BA AC 33 06 03 E8 ?? ?? ?? ?? }

		// ----------------------------------------
		// Function: init_frame_info
		// ----------------------------------------
		/*
		 * 48 83 EC 20                   sub rsp, 0x20
		 * B9 5B BC 4A 6A                mov ecx, 0x6A4ABC5B
		 * BA 04 49 32 D3                mov edx, 0xD3324904
		 * E8 2B F8 FF FF                call resolve
		 * (Score: 520)
		 */
		$r6_init_frame_info = { 48 83 EC 20 B9 5B BC 4A 6A BA 04 49 32 D3 E8 ?? ?? ?? ?? }

		// ----------------------------------------
		// Function: calculate_function_stack_size_wrapper
		// ----------------------------------------
		/*
		 * 48 83 EC 20                   sub rsp, 0x20
		 * B9 5B BC 4A 6A                mov ecx, 0x6A4ABC5B
		 * BA D9 46 D8 C1                mov edx, 0xC1D846D9
		 * E8 0E F6 FF FF                call resolve
		 * (Score: 520)
		 */
		$r7_calculate_function_stack_size_wrapper = { 48 83 EC 20 B9 5B BC 4A 6A BA D9 46 D8 C1 E8 ?? ?? ?? ?? }

		// ----------------------------------------
		// Function: _LoadLibraryA
		// ----------------------------------------
		/*
		 * 48 83 EC 20                   sub rsp, 0x20
		 * B9 5B BC 4A 6A                mov ecx, 0x6A4ABC5B
		 * BA 8E 4E 0E EC                mov edx, 0xEC0E4E8E
		 * E8 F7 F2 FF FF                call resolve
		 * (Score: 520)
		 */
		$r8_LoadLibraryA = { 48 83 EC 20 B9 5B BC 4A 6A BA 8E 4E 0E EC E8 ?? ?? ?? ?? }

		// ----------------------------------------
		// Function: _VirtualAlloc
		// ----------------------------------------
		/*
		 * 48 83 EC 20                   sub rsp, 0x20
		 * B9 5B BC 4A 6A                mov ecx, 0x6A4ABC5B
		 * BA 54 CA AF 91                mov edx, 0x91AFCA54
		 * E8 C9 E0 FF FF                call resolve
		 * (Score: 520)
		 */
		$r9_VirtualAlloc = { 48 83 EC 20 B9 5B BC 4A 6A BA 54 CA AF 91 E8 ?? ?? ?? ?? }

	condition:
		5 of them
}

