//go:build darwin

package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/lhg-projects/lhg-lanclip/internal/crypto"
	"github.com/lhg-projects/lhg-lanclip/internal/discovery"
	"github.com/lhg-projects/lhg-lanclip/internal/pair"
	"github.com/lhg-projects/lhg-lanclip/internal/settings"
)

// guiSupported gates the Fyne panel to darwin for now (Windows/Linux keep
// the headless + systray builds; their CI cannot build cgo GUI deps yet).
func guiSupported() bool { return true }

// runGUI shows the settings window and the menu-bar icon together under one
// Fyne driver. Blocks the main goroutine until quit. On firstRun (fresh
// install) the settings panel opens immediately; afterwards the app lives in
// the menu bar until invoked.
func runGUI(srv *serveStack, firstRun bool) {
	a := app.NewWithID("io.lhg-projects.lanclip")

	win := a.NewWindow("LanClip 设置")
	win.Resize(fyne.NewSize(560, 640))
	win.SetCloseIntercept(func() { win.Hide() }) // stay in menu bar

	// ---------- live widgets ----------
	statusLabel := widget.NewLabel("…")
	pinLabel := widget.NewLabel("")
	var peersList *widget.List
	var filesList *widget.List
	var peerObjs []discovery.Peer
	var fileObjs []os.FileInfo

	refreshStatus := func() {
		n := len(srv.peersFunc())
		pin, _ := pinOf(srv.groupKey)
		if paused.Load() {
			statusLabel.SetText(fmt.Sprintf("已暂停 · 局域网内发现 %d 台设备", n))
		} else {
			statusLabel.SetText(fmt.Sprintf("同步中 · 局域网内发现 %d 台设备", n))
		}
		pinLabel.SetText(fmt.Sprintf("配对校验码（两台设备必须一致）：%s", pin))
		if peersList != nil {
			peerObjs = srv.peersFunc()
			peersList.Refresh()
		}
	}

	// ---------- 设置卡片：同步开关 ----------
	st := srv.settings.Get()
	textSw := widget.NewCheck("", nil)
	textSw.SetChecked(st.SyncText)
	imgSw := widget.NewCheck("", nil)
	imgSw.SetChecked(st.SyncImages)
	fileSw := widget.NewCheck("", nil)
	fileSw.SetChecked(st.SyncFiles)
	applyToggles := func() {
		syncPrefs.mu.Lock()
		syncPrefs.text = textSw.Checked
		syncPrefs.images = imgSw.Checked
		syncPrefs.files = fileSw.Checked
		syncPrefs.mu.Unlock()
		_ = srv.settings.Update(func(c *settings.Settings) {
			c.SyncText = textSw.Checked
			c.SyncImages = imgSw.Checked
			c.SyncFiles = fileSw.Checked
		})
	}
	textSw.OnChanged = func(bool) { applyToggles() }
	imgSw.OnChanged = func(bool) { applyToggles() }
	fileSw.OnChanged = func(bool) { applyToggles() }

	// ---------- 收件目录 ----------
	dirLabel := widget.NewLabel(st.SaveDir)
	dirLabel.Wrapping = fyne.TextTruncate
	restartHint := widget.NewLabel("")
	dirBtn := widget.NewButton("选择目录…", func() {
		dialog.NewFolderOpen(func(lu fyne.ListableURI, err error) {
			if err != nil || lu == nil {
				return
			}
			dir := strings.TrimPrefix(lu.Path(), "file://")
			dirLabel.SetText(dir)
			_ = srv.settings.Update(func(c *settings.Settings) { c.SaveDir = dir })
			restartHint.SetText("收件目录已保存，重启 LanClip 后生效")
		}, win).Show()
	})

	// ---------- 设备名 ----------
	nameEntry := widget.NewEntry()
	nameEntry.SetText(st.DeviceName)
	nameEntry.OnChanged = func(s string) {
		_ = srv.settings.Update(func(c *settings.Settings) {
			c.DeviceName = strings.TrimSpace(s)
		})
	}

	// ---------- 配对 ----------
	pairLog := widget.NewLabel("尚未开始配对")
	pairLog.Wrapping = fyne.TextWrapWord
	var pairing atomic.Bool
	var pairBtn *widget.Button
	pairBtn = widget.NewButton("生成一次性配对码（5 分钟有效）", func() {
		if pairing.Load() {
			return
		}
		pairing.Store(true)
		pairBtn.Disable()
		go func() {
			defer func() { pairing.Store(false); pairBtn.Enable() }()
			err := pair.Listen(srv.groupKey, srv.deviceID, srv.settings.Get().DeviceName, func(f string, args ...any) {
				msg := fmt.Sprintf(f, args...)
				fmt.Println("[pair]", msg)
				pinLabel.SetText(msg)
				pairLog.SetText(msg)
			})
			if err != nil {
				pairLog.SetText("配对结束：" + err.Error())
			}
		}()
	})
	keyEntry := widget.NewEntry()
	keyEntry.SetPlaceHolder("粘贴 lanclip key-export 输出的 base64 密钥")
	importBtn := widget.NewButton("导入密钥配对", func() {
		go importKeyGUI(win, srv, keyEntry, pairLog)
	})

	// ---------- 已配对/在线设备列表 ----------
	peersList = widget.NewList(
		func() int { return len(peerObjs) },
		func() fyne.CanvasObject {
			return container.NewBorder(nil, nil, nil,
				widget.NewLabel(""),
				container.NewVBox(widget.NewLabel(""), widget.NewLabel("")))
		},
		func(i widget.ListItemID, o fyne.CanvasObject) {
			if i >= len(peerObjs) {
				return
			}
			p := peerObjs[i]
			b := o.(*fyne.Container).Objects[0].(*fyne.Container)
			name := b.Objects[0].(*widget.Label)
			meta := b.Objects[1].(*widget.Label)
			name.SetText(fmt.Sprintf("🖥  %s", p.DeviceName))
			meta.SetText(fmt.Sprintf("%s · %s · %s", p.Platform, p.DeviceID[:8], p.Addr))
		},
	)

	// ---------- 收到的文件 ----------
	filesList = widget.NewList(
		func() int { return len(fileObjs) },
		func() fyne.CanvasObject {
			return container.NewBorder(nil, nil, nil, widget.NewButton("Finder 中显示", nil),
				container.NewVBox(widget.NewLabel(""), widget.NewLabel("")))
		},
		func(i widget.ListItemID, o fyne.CanvasObject) {
			if i >= len(fileObjs) {
				return
			}
			fi := fileObjs[i]
			box := o.(*fyne.Container).Objects[0].(*fyne.Container)
			name := box.Objects[0].(*widget.Label)
			meta := box.Objects[1].(*widget.Label)
			name.SetText("📄  " + fi.Name())
			meta.SetText(fmt.Sprintf("%s · %.1f KB", fi.ModTime().Format("01-02 15:04"), float64(fi.Size())/1024))
			btn := o.(*fyne.Container).Objects[1].(*widget.Button)
			btn.OnTapped = func() {
				revealInFinder(filepath.Join(srv.settings.Get().SaveDir, fi.Name()))
			}
		},
	)
	refreshFiles := func() {
		entries, err := os.ReadDir(srv.settings.Get().SaveDir)
		if err != nil {
			return
		}
		fileObjs = nil
		for _, en := range entries {
			if info, err := en.Info(); err == nil && info.Mode().IsRegular() {
				fileObjs = append(fileObjs, info)
			}
		}
		sort.Slice(fileObjs, func(i, j int) bool { return fileObjs[i].ModTime().After(fileObjs[j].ModTime()) })
		filesList.Refresh()
	}
	refreshFilesBtn := widget.NewButtonWithIcon("刷新", theme.ViewRefreshIcon(), refreshFiles)

	// ---------- 布局 ----------
	card := func(title string, items ...fyne.CanvasObject) fyne.CanvasObject {
		return container.NewVBox(append([]fyne.CanvasObject{
			widget.NewLabelWithStyle(title, fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		}, items...)...)
	}

	toggles := container.NewGridWithColumns(2,
		widget.NewLabel("同步剪贴板文本"), textSw,
		widget.NewLabel("同步截图/图片"), imgSw,
		widget.NewLabel("同步复制的文件"), fileSw,
		widget.NewLabel(""), widget.NewLabel(""),
	)

	scroll := container.NewVScroll(container.NewVBox(
		card("状态", statusLabel, pinLabel),
		widget.NewSeparator(),
		card("同步开关", toggles),
		widget.NewSeparator(),
		card("收件目录", dirLabel, dirBtn, restartHint),
		card("本机设备名（重启后生效）", nameEntry),
		widget.NewSeparator(),
		card("配对新设备",
			container.NewGridWithColumns(1, pairBtn),
			keyEntry,
			importBtn,
			pairLog),
		widget.NewSeparator(),
		card("在线设备", peersList),
		widget.NewSeparator(),
		card("收到的文件（"+filepath.Base(srv.settings.Get().SaveDir)+"）",
			container.NewBorder(nil, nil, nil, refreshFilesBtn, filesList)),
	))
	win.SetContent(scroll)

	// ---------- 托盘 ----------
	if desk, ok := a.(desktop.App); ok {
		desk.SetSystemTrayIcon(fyne.NewStaticResource("tray", iconTemplatePNG))
		mPanel := fyne.NewMenuItem("打开设置面板…", func() { win.Show(); win.RequestFocus() })
		mPause := fyne.NewMenuItem("暂停同步", nil)
		mPause.Action = func() {
			paused.Store(!paused.Load())
			if paused.Load() {
				mPause.Label = "恢复同步"
			} else {
				mPause.Label = "暂停同步"
			}
			refreshStatus()
		}
		mQuit := fyne.NewMenuItem("退出 LanClip", func() { a.Quit() })
		desk.SetSystemTrayMenu(fyne.NewMenu("LanClip", mPanel, mPause, mQuit))
	}

	// periodic refresh
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for range t.C {
			refreshStatus()
			refreshFiles()
		}
	}()
	refreshStatus()

	fmt.Println("gui: 设置面板已就绪（菜单栏图标 → 打开设置面板…）")
	if firstRun {
		win.Show()
	}
	a.Run()
	fmt.Println("gui: 已退出")
}

func pinOf(groupKey []byte) (string, error) {
	return crypto.DerivePINBytes(groupKey)
}

func revealInFinder(path string) {
	_ = exec.Command("open", "-R", path).Start()
}

// importGroupKey validates and installs a base64 group key, returning the
// resulting pairing PIN.
func importGroupKey(b64 string) (string, error) {
	k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return "", fmt.Errorf("不是有效的 base64")
	}
	if len(k) != crypto.GroupKeyLen {
		return "", fmt.Errorf("密钥长度不对（%d 字节）", len(k))
	}
	path := filepath.Join(configDir(), "group.key")
	if err := os.WriteFile(path, k, 0o600); err != nil {
		return "", err
	}
	return crypto.DerivePINBytes(k)
}

func importKeyGUI(_ fyne.Window, srv *serveStack, entry *widget.Entry, logw *widget.Label) {
	b64 := strings.TrimSpace(entry.Text)
	if b64 == "" {
		logw.SetText("请先粘贴密钥")
		return
	}
	pin, err := importGroupKey(b64)
	if err != nil {
		logw.SetText("导入失败：" + err.Error())
		return
	}
	logw.SetText(fmt.Sprintf("导入成功，新校验码 %s。重启 LanClip 后生效。", pin))
}
