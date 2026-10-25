# LanClip — 局域网剪贴板与文件同步

**手机复制、电脑粘贴；电脑截图、手机粘贴。无需任何服务器、无需登录。**

LanClip 是一个开源的、纯局域网的跨设备剪贴板同步工具。它的设计灵感来自对微信输入法「跨设备粘贴」功能的逆向分析（见 [docs/REVERSE-ENGINEERING-REPORT.md](docs/REVERSE-ENGINEERING-REPORT.md)），但这是一个**完全独立重写**的实现：不包含、不依赖、也不兼容微信输入法的任何代码或协议。

## 功能

- **文本同步**：任一设备复制文字，同组其他设备自动收到并写入剪贴板
- **图片/截图同步**：剪贴板图片自动互传；**macOS 按 ⌘⇧3/⌘⇧4 的截图无需任何操作**——shotwatch 监听截图目录，新截图自动推到对端剪贴板（中英文文件名均可，老文件不重发，可用"同步截图/图片"开关一键停用）
- **文件互传**：任意大小文件，流式分块传输（100MB 实测接收端内存恒定 ~24MB），**中断可续传**（接收端保留 `.partial`，重发时按已收字节数续传，实测 1GB 文件 500MB 处续传成功）
- **菜单栏/托盘**（macOS/Windows）：实时显示对端数量、一键暂停/恢复同步、退出；`LANCLIP_NO_TRAY=1` 关闭
- **自动发现**：mDNS/Bonjour 自动发现同局域网设备，扫码/输码都不需要
- **安全**：TLS 1.3 传输加密 + 组密钥 HMAC 握手（同网段陌生设备无法接入）+ 配对 PIN 确认

## 快速开始

### macOS（安装包）

从 [Releases](https://github.com/lhg-projects/lhg-lanclip/releases) 下载 `LanClip-x.y.z-universal.dmg`
（或自行构建：`./scripts/macos-dmg.sh`），打开后把 **LanClip** 拖进 **Applications**，双击启动：

- 它是菜单栏常驻应用（Dock 无图标），启动即进入剪贴板同步服务
- **首次启动会自动弹出设置面板**；之后随时从菜单栏图标 → 「打开设置面板…」进入
- 设置面板功能：
  - 状态与配对校验码（PIN）一览
  - 同步开关：文本 / 截图图片 / 复制文件，实时生效
  - 收件目录选择、本机设备名修改
  - 一键生成 5 分钟一次性配对码，或粘贴 base64 密钥导入配对
  - 在线设备列表（实时刷新）；收到的文件列表（可一键在 Finder 中显示）
- 运行日志：`~/.config/lanclip/lanclip.log`（`tail -f` 可看收发记录）
- 两台 Mac 都装好后，用 `lanclip key-export` / `key-import` 配对（见下）
- 首次启动 macOS 会询问"本地网络"权限，点允许

命令行工具与 .app 二进制相同：

```bash
/Applications/LanClip.app/Contents/MacOS/lanclip peers
```

### macOS（源码构建）

```bash
# 构建（需要 Go 1.24+）
go build -o lanclip ./cmd/lanclip

# 设备 A（比如电脑）
./lanclip serve

# 设备 B（比如另一台电脑）——先配对，再启动：
./lanclip key-import "$(在A上执行 lanclip key-export 输出的base64)"
./lanclip serve
```

配对后两台设备显示相同的 `lanclip pin`（6 位校验码，务必人工确认一致），之后任意一台复制文字/截图都会自动同步到另一台。

### 手动发送

```bash
./lanclip peers              # 列出局域网内的设备
./lanclip send-text "你好"   # 发送文字给发现的设备
./lanclip send-file a.pdf b.zip
./lanclip pin                # 查看本机配对 PIN
```

### Windows

```powershell
set GOOS=windows
go build -o lanclip.exe ./cmd/lanclip
lanclip.exe serve
```

（Windows 端文本与图片同步均已实现：图片走 CF_DIBV5 ↔ PNG 转换，覆盖 32bpp/24bpp 截图格式。）

### 测试/多实例

环境变量 `LANCLIP_DIR`（配置目录）和 `LANCLIP_PORT`（监听端口）可以在一台机器上模拟多设备。

## 架构

```
┌────────────────────────────────────────────────┐
│ cmd/lanclip         CLI + serve 守护进程        │
├────────────────────────────────────────────────┤
│ internal/clipboard  NSPasteboard(darwin) /     │
│                     user32(windows) 剪贴板监听  │
│ internal/discovery  mDNS 广播 + 浏览            │
│ internal/transfer   TLS1.3 + 帧协议 + 分块传输  │
│ internal/crypto     组密钥 / HMAC / 配对PIN     │
│ internal/protocol   帧格式（JSON 信封 + 二进制块）│
└────────────────────────────────────────────────┘
```

传输协议要点（对应逆向报告中微信输入法的设计，全部用开放格式重新实现）：

| 设计点 | 做法 |
|---|---|
| 设备发现 | mDNS `_lanclip._tcp`，TXT 记录携带 deviceID/平台/版本 |
| 身份认证 | TLS 1.3 + Hello 帧 HMAC-SHA256(groupKey)，握不过直接断开 |
| 防回环/去重 | 每条剪贴板带 deviceID + 单调 version（unix nano），接收端按设备去重；发送端按内容哈希防自回声 |
| 图片 | 图片以 image-ref 帧宣告，随后在**同一条连接**上流式拉取，不整包塞帧 |
| 文件 | manifest 帧宣告一批文件 → 256KB 分块（逐块 sha256 + 严格顺序偏移校验）→ `.partial` 落盘 + 原子 rename + 整文件 sha256 终验 |
| 大文件 | 发送端 `io.Copy` 流式读取，接收端边收边写，内存恒定 |
| 配对 | 首台设备生成随机 group.key（32B），`key-export`/`key-import` 导入新设备；两端 PIN 相互确认（SAS） |
| 认证 | Hello 帧的 HMAC 以 **TLS exporter** 为输入，绑定当前连接——中间人无法用自己的两条连接转发重放标签 |

## 交付范围与说明

- ✅ macOS：文本 + 图片 + 文件（已双实例实测，100MB 文件、PNG 截图、中英文文本）
- ✅ Windows：构建通过，文本同步可用；图片/文件路径代码与 macOS 共用，剪贴板图片写入待完善
- ⏳ 手机端（Android/iOS）：见下

## 手机端现状与接入

| 端 | 状态 | 说明 |
|---|---|---|
| Android | ✅ **v0.5.0 客户端已实现**（`android/`） | 前台服务接收 + NSD 发现 + 截图自动推送 + 系统分享发送 + 配对；见下「Android 使用」 |
| iOS | 暂不支持（按需求出局） | — |

### Android 使用（真机步骤）

1. 电脑启动：`LANCLIP_API_PORT=47719 LANCLIP_API_BIND=lan lanclip serve`（或 .app + 环境变量）
2. 电脑 `lanclip key-export` 复制输出的 base64 → App「配对」粘贴 → 两边 PIN 一致即成功
3. App 点「启动同步」→ 授权通知/相册权限
4. 手机截图 → 自动出现在电脑剪贴板（⌘V 粘贴）；电脑截图 → 手机相册 lanclip + 通知
5. 电脑托盘菜单「发送文件到 <手机名>」选文件 → 手机 Download/lanclip
6. 手机任何 App 分享 → LanClip → 选电脑 → 到达电脑剪贴板/收件目录

（App 内"发送剪贴板"按钮补足安卓系统不允许后台读剪贴板的限制。）

构建：`cd android && ./gradlew assembleDebug`（JDK 17 + Android SDK 34）。

> 桌面端 serve 模式已经把接收方的文件落在 `received/` 目录，手机互传文件时接收路径同样适用。

## 环境变量

| 变量 | 作用 | 默认 |
|---|---|---|
| `LANCLIP_DIR` | 配置/收件目录 | `~/.config/lanclip` |
| `LANCLIP_PORT` | 同步监听端口 | 47717 |
| `LANCLIP_API_PORT` | 本地 HTTP API 端口（手机/快捷指令接入） | 未启用 |
| `LANCLIP_PEERS` | 静态对端地址（逗号分隔，mDNS 不可用时兜底） | 未启用 |
| `LANCLIP_NO_TRAY` | `1` = 不启动菜单栏/托盘（服务器/CI 场景） | 未设置 |
| `LANCLIP_NO_GUI` | `1` = .app 模式下退回纯托盘（无设置面板） | 未设置 |
| `LANCLIP_INSECURE_OPEN` | `1` = 接受未配对设备（**不建议**） | 未设置 |

## 安全模型

- **传输**：TLS 1.3（每安装一份自签证书），局域网内嗅探不可读。
- **认证**：Hello 帧 HMAC = `HMAC(groupKey, "lanclip-hello-v2" || TLS-exporter || deviceID)`。因为 MAC 输入包含本连接的 TLS exporter 值，中间人各持一条 TLS 连接也无法把合法标签转发到自己的连接上使用——重放即失效。
- **输入消毒**：远端文件名经 `SanitizeFileName` 压平为单一路径元素（拒绝 `../`、绝对路径、反斜杠、NUL），永远落不出 `received/` 目录。
- **资源上限**：JSON 帧 ≤4MB；分块数据 ≤256KB（超出直接断开）；剪贴板图片 ≤32MB；文件走磁盘流式，无内存上限问题。

## 注意事项（大文件 / 内存）

逆向微信输入法时发现它对剪贴板图片设了 100MB 上限（因为云中转路径必须缓存整个文件）。LanClip 走局域网直连 + 全程流式，文件传输理论上没有实际上限；当前保护措施：

- 单帧 JSON（元数据）上限 4MB，文件内容**永远**不走 JSON 帧；
- 256KB 分块 + 逐块 sha256 + 严格顺序偏移校验 + 整文件 sha256 终验，坏块/乱序直接报错终止；
- 接收端先写 `.partial` 再原子改名，中断不会留下半个可用文件；
- 1MB 以上的纯文本建议走 `send-file`（文本内联上限 1MB）。

## 路线图

- [x] 断点续传（v0.3，manifest-ack 偏移协商）
- [x] serve 模式本地 HTTP API（`LANCLIP_API_PORT`，/api/peers、/api/send-text、/api/shot）
- [x] 菜单栏/托盘 GUI（v0.3，macOS/Windows）
- [ ] 多设备并发推送（当前发送端逐台推送）
- [x] HTTP API 放开局域网 + HMAC 鉴权（v0.5，Android 对端通道）
- [x] Windows 截图监听（Pictures/Screenshots，v0.5）
- [ ] Android 剪贴板服务化监听（系统限制，等方案：无障碍/输入法法）

## 许可

MIT。本项目与腾讯/微信无任何关联；逆向分析仅用于理解机制并启发独立实现，报告中不包含、本仓库也不分发任何原应用的代码或资源。
