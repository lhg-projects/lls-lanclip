//go:build darwin || windows

package main

import (
	_ "embed"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"fyne.io/systray"
	"github.com/lhg-projects/lhg-lanclip/internal/discovery"
)

//go:embed icon_template.png
var iconTemplatePNG []byte

//go:embed icon.ico
var iconICO []byte

// sendSlots is the number of dynamic "send file to <peer>" tray entries.
const sendSlots = 8

// pickFileNative opens the platform file picker and returns the chosen path
// ("" when cancelled).
func pickFileNative() string {
	if runtime.GOOS == "darwin" {
		out, err := exec.Command("osascript", "-e", `POSIX path of (choose file with prompt "选择要发送的文件")`).Output()
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(out))
	}
	// windows: PowerShell STA OpenFileDialog
	script := `Add-Type -AssemblyName System.Windows.Forms; $f = New-Object System.Windows.Forms.OpenFileDialog; if ($f.ShowDialog() -eq 'OK') { Write-Output $f.FileName }`
	out, err := exec.Command("powershell", "-NoProfile", "-STA", "-Command", script).Output()
	if err != nil {
		return ""
	}
	p := strings.TrimSpace(string(out))
	if p == "" || p == "$null" {
		return ""
	}
	return p
}

// runTray shows the menu-bar / system-tray item and blocks until the user
// quits from the menu. Must be called from the main goroutine (macOS rule);
// helper goroutines are allowed to outlive it until process exit.
func runTray(stack *serveStack, paused *atomic.Bool) {
	onReady := func() {
		if runtime.GOOS == "darwin" {
			systray.SetTemplateIcon(iconTemplatePNG, iconTemplatePNG)
		} else {
			systray.SetIcon(iconICO)
		}
		systray.SetTitle("LanClip")
		systray.SetTooltip("局域网剪贴板同步（点击菜单暂停/发送文件/退出）")

		mStatus := systray.AddMenuItem("对端: 探索中…", "已发现的设备数")
		mStatus.Disable()
		systray.AddSeparator()
		mPause := systray.AddMenuItem("暂停同步", "暂停本机剪贴板外发")
		systray.AddSeparator()

		systray.AddMenuItem("── 发送文件到 …", "").Disable()
		var slots []*systray.MenuItem
		for i := 0; i < sendSlots; i++ {
			m := systray.AddMenuItem("", "")
			m.Hide()
			slots = append(slots, m)
			go func(slot int) {
				for range slots[slot].ClickedCh {
					ps := stack.peersFunc()
					if slot >= len(ps) {
						continue
					}
					path := pickFileNative()
					if path == "" {
						continue
					}
					target := ps[slot]
					if n := sendFileTo(stack, []discovery.Peer{target}, filepath.Base(path), path); n > 0 {
						fmt.Printf("[-> file] %s → %s (%s)\n", filepath.Base(path), target.DeviceName, target.Platform)
					}
				}
			}(i)
		}

		systray.AddSeparator()
		mQuit := systray.AddMenuItem("退出 LanClip", "退出后台服务")

		go func() {
			for range mPause.ClickedCh {
				if paused.Swap(!paused.Load()) {
					mPause.SetTitle("暂停同步")
					mPause.SetTooltip("暂停本机剪贴板外发")
				} else {
					mPause.SetTitle("恢复同步")
					mPause.SetTooltip("恢复本机剪贴板外发")
				}
			}
		}()
		go func() {
			for range mQuit.ClickedCh {
				systray.Quit()
				return
			}
		}()
		go func() {
			t := time.NewTicker(3 * time.Second)
			defer t.Stop()
			for range t.C {
				ps := stack.peersFunc()
				mStatus.SetTitle(fmt.Sprintf("对端: %d 台设备", len(ps)))
				for i, m := range slots {
					if i < len(ps) {
						plat := ps[i].Platform
						if plat == "" {
							plat = "?"
						}
						m.SetTitle(fmt.Sprintf("%s (%s)", ps[i].DeviceName, plat))
						m.Show()
					} else {
						m.Hide()
					}
				}
			}
		}()
	}
	systray.Run(onReady, func() {})
}

// traySupported reports whether this build shows a tray at all.
func traySupported() bool { return true }
