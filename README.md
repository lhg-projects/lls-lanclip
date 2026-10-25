# LanClip — 局域网剪贴板与文件同步

**手机复制、电脑粘贴；电脑截图、手机粘贴。无需任何服务器、无需登录。**

LanClip 是一个开源的、纯局域网的跨设备剪贴板同步工具。它的设计灵感来自对微信输入法「跨设备粘贴」功能的逆向分析（见 [docs/REVERSE-ENGINEERING-REPORT.md](docs/REVERSE-ENGINEERING-REPORT.md)），但这是一个**完全独立重写**的实现：不包含、不依赖、也不兼容微信输入法的任何代码或协议。

## 功能

- **文本同步**：任一设备复制文字，同组其他设备自动收到并写入剪贴板
- **图片/截图同步**：手机截图 → 电脑剪贴板直接 ⌘V 粘贴；电脑截图 → 手机
- **文件互传**：任意大小文件，流式分块传输（100MB 实测接收端内存恒定 ~24MB），**中断可续传**（接收端保留 `.partial`，重发时按已收字节数续传，实测 1GB 文件 500MB 处续传成功）
- **菜单栏/托盘**（macOS/Windows）：实时显示对端数量、一键暂停/恢复同步、退出；`LANCLIP_NO_TRAY=1` 关闭
- **自动发现**：mDNS/Bonjour 自动发现同局域网设备，扫码/输码都不需要
- **安全**：TLS 1.3 传输加密 + 组密钥 HMAC 握手（同网段陌生设备无法接入）+ 配对 PIN 确认

## 快速开始

### macOS

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

## 手机端怎么接入？

用户的核心场景是「手机截图 ↔ 电脑粘贴」。LanClip 的协议是开放的，手机端有两种接入方式：

1. **Android App（推荐路线）**：Android 原生可以直接用 `NsdManager`（mDNS）发现设备、`ClipboardManager` 监听剪贴板、普通 Socket + TLS 连接桌面端。协议里没有任何平台绑定，照着 `internal/protocol` 实现即可。
2. **iOS**：由于 iOS 无法常驻监听剪贴板（系统限制），可做成分享扩展 / 快捷指令（Shortcuts）调用 `send-text`/`send-file` 的 HTTP 桥（可在 serve 模式下加一个本地 HTTP API）。

> 桌面端 serve 模式已经把接收方的文件落在 `received/` 目录，手机互传文件时接收路径同样适用。

## 环境变量

| 变量 | 作用 | 默认 |
|---|---|---|
| `LANCLIP_DIR` | 配置/收件目录 | `~/.config/lanclip` |
| `LANCLIP_PORT` | 同步监听端口 | 47717 |
| `LANCLIP_API_PORT` | 本地 HTTP API 端口（手机/快捷指令接入） | 未启用 |
| `LANCLIP_PEERS` | 静态对端地址（逗号分隔，mDNS 不可用时兜底） | 未启用 |
| `LANCLIP_NO_TRAY` | `1` = 不启动菜单栏/托盘（服务器/CI 场景） | 未设置 |
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

## 许可

MIT。本项目与腾讯/微信无任何关联；逆向分析仅用于理解机制并启发独立实现，报告中不包含、本仓库也不分发任何原应用的代码或资源。
