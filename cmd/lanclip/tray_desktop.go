//go:build darwin || windows

package main

import (
	_ "embed"
	"fmt"
	"runtime"
	"sync/atomic"
	"time"

	"fyne.io/systray"
	"github.com/lhg-projects/lhg-lanclip/internal/discovery"
	"github.com/lhg-projects/lhg-lanclip/internal/transfer"
)

//go:embed icon_template.png
var iconTemplatePNG []byte

//go:embed icon.ico
var iconICO []byte

// runTray shows the menu-bar / system-tray item and blocks until the user
// quits from the menu. Must be called from the main goroutine (macOS rule);
// helper goroutines are allowed to outlive it until process exit.
func runTray(_ *transfer.Engine, peers func() []discovery.Peer, paused *atomic.Bool) {
	onReady := func() {
		if runtime.GOOS == "darwin" {
			systray.SetTemplateIcon(iconTemplatePNG, iconTemplatePNG)
		} else {
			systray.SetIcon(iconICO)
		}
		systray.SetTitle("LanClip")
		systray.SetTooltip("局域网剪贴板同步（点击菜单暂停/退出）")

		mStatus := systray.AddMenuItem("对端: 探索中…", "已发现的设备数")
		mStatus.Disable()
		systray.AddSeparator()
		mPause := systray.AddMenuItem("暂停同步", "暂停本机剪贴板外发")
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
				mStatus.SetTitle(fmt.Sprintf("对端: %d 台设备", len(peers())))
			}
		}()
	}
	systray.Run(onReady, func() {})
}

// traySupported reports whether this build shows a tray at all.
func traySupported() bool { return true }
