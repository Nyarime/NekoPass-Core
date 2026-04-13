//go:build windows

package main

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

// requestAdmin 检测是否管理员，不是则UAC提升重启
func requestAdmin() {
	if isAdmin() {
		return
	}
	// 用runas重新启动自己
	exe, _ := os.Executable()
	args := strings.Join(os.Args[1:], " ")
	cmd := exec.Command("cmd", "/C", "start", "", "/B", exe, args)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow: true,
	}
	// 使用ShellExecute runas
	verb := "runas"
	cmd = exec.Command(exe, os.Args[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	// Windows ShellExecute
	shell32 := syscall.NewLazyDLL("shell32.dll")
	shellExecute := shell32.NewProc("ShellExecuteW")
	exeW, _ := syscall.UTF16PtrFromString(exe)
	argsW, _ := syscall.UTF16PtrFromString(args)
	verbW, _ := syscall.UTF16PtrFromString(verb)
	dirW, _ := syscall.UTF16PtrFromString("")
	shellExecute.Call(0, uintptr(unsafe.Pointer(verbW)), uintptr(unsafe.Pointer(exeW)),
		uintptr(unsafe.Pointer(argsW)), uintptr(unsafe.Pointer(dirW)), 1)
	os.Exit(0)
}

func isAdmin() bool {
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	return err == nil
}
