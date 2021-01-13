package main

import (
	"syscall"

	"github.com/synzack/sys/windows"
)

func main() {
	text, _ := syscall.UTF16PtrFromString("test message")
	header, _ := syscall.UTF16PtrFromString("header test")

	windows.MessageBox(0, text, header, 0)
}
