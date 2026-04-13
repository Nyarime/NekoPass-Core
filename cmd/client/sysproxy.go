package main

import (
	"log"
	"os/exec"
	"runtime"
)

// setSystemProxy 设置系统代理
func setSystemProxy(addr string) {
	switch runtime.GOOS {
	case "darwin":
		// macOS: networksetup
		exec.Command("networksetup", "-setwebproxy", "Wi-Fi", "127.0.0.1", extractPort(addr)).Run()
		exec.Command("networksetup", "-setsecurewebproxy", "Wi-Fi", "127.0.0.1", extractPort(addr)).Run()
		exec.Command("networksetup", "-setsocksfirewallproxy", "Wi-Fi", "127.0.0.1", extractPort(addr)).Run()
		log.Printf("[Proxy] 系统代理已设置: %s", addr)
	case "windows":
		exec.Command("reg", "add", `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`,
			"/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "1", "/f").Run()
		exec.Command("reg", "add", `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`,
			"/v", "ProxyServer", "/t", "REG_SZ", "/d", addr, "/f").Run()
		log.Printf("[Proxy] 系统代理已设置: %s", addr)
	case "linux":
		// GNOME
		exec.Command("gsettings", "set", "org.gnome.system.proxy", "mode", "manual").Run()
		exec.Command("gsettings", "set", "org.gnome.system.proxy.http", "host", "127.0.0.1").Run()
		exec.Command("gsettings", "set", "org.gnome.system.proxy.http", "port", extractPort(addr)).Run()
		exec.Command("gsettings", "set", "org.gnome.system.proxy.socks", "host", "127.0.0.1").Run()
		exec.Command("gsettings", "set", "org.gnome.system.proxy.socks", "port", extractPort(addr)).Run()
		log.Printf("[Proxy] 系统代理已设置: %s", addr)
	}
}

// clearSystemProxy 恢复系统代理
func clearSystemProxy() {
	switch runtime.GOOS {
	case "darwin":
		exec.Command("networksetup", "-setwebproxystate", "Wi-Fi", "off").Run()
		exec.Command("networksetup", "-setsecurewebproxystate", "Wi-Fi", "off").Run()
		exec.Command("networksetup", "-setsocksfirewallproxystate", "Wi-Fi", "off").Run()
		log.Printf("[Proxy] 系统代理已恢复")
	case "windows":
		exec.Command("reg", "add", `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`,
			"/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f").Run()
		log.Printf("[Proxy] 系统代理已恢复")
	case "linux":
		exec.Command("gsettings", "set", "org.gnome.system.proxy", "mode", "none").Run()
		log.Printf("[Proxy] 系统代理已恢复")
	}
}

func extractPort(addr string) string {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[i+1:]
		}
	}
	return "1080"
}
