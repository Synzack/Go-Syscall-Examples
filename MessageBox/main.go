package main

import (
	"syscall"
	"unsafe"
)

const (
	MB_ABORTRETRYIGNORE  = 0x00000002
	MB_CANCELTRYCONTINUE = 0x00000006
	MB_HELP              = 0x00004000
	MB_OK                = 0x00000000
	MB_OKCANCEL          = 0x00000001
	MB_RETRYCANCEL       = 0x00000005
	MB_YESNO             = 0x00000004
)

func main() {
	text, _ := syscall.UTF16PtrFromString("test message")
	header, _ := syscall.UTF16PtrFromString("header test")

	user32 := syscall.NewLazyDLL("User32.dll")
	messageBox := user32.NewProc("MessageBoxW")

	messageBox.Call(
		uintptr(0),
		uintptr(unsafe.Pointer(text)),
		uintptr(unsafe.Pointer(header)),
		uintptr(MB_OKCANCEL))
}
