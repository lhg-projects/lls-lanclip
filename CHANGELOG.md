# Changelog

## 0.4.0 (2026-10-25)

**设置面板（macOS .app）**：Fyne 实现的原生窗口，菜单栏图标 → 「打开设置面板…」；
首次安装自动弹出。功能：

- 状态卡：同步中/已暂停、在线设备数、配对校验码（PIN）
- 同步开关：文本 / 截图图片 / 复制文件，**实时生效**并持久化到 `settings.json`
- 收件目录选择器、本机设备名编辑（重启生效，界面有提示）
- 配对：生成 5 分钟一次性 PIN（internal/pair），或粘贴 base64 密钥导入
- 在线设备列表（2 秒刷新）、收到的文件列表（按时间排序、一键 Finder 定位）
- 托盘菜单升级：打开设置面板 / 暂停恢复 / 退出

**架构**：

- `runServe` 拆分为可复用的 `startServe` 守护栈（引擎/监听/mDNS/剪贴板/CLI 与 GUI 共用）
- 新增 `internal/settings` 持久化包（原子写入、损坏自动回退默认）+ 单测
- GUI 仅 darwin 构建（`gui_darwin.go`），Windows/Linux 保持纯 CLI+托盘，CI 不受影响
- .app 首次启动检测（无 settings.json 时弹面板）

## 0.3.0 (2026-10-25)

**断点续传**：接收端为每个传入文件保留 `.partial`；重发同一文件时接收端通过新增的
`manifest_ack` 帧申报已收字节数，发送端 seek 到偏移处只补传剩余部分（兼容 0.2 旧对端：
旧版不读 ack，直接全量重传，行为不变）。最终 sha256 校验失败会清除损坏的 `.partial`
避免死循环。实测：1GB 文件在 500MB 处中断后续传，2.4 秒补完剩余部分，MD5 一致。

**菜单栏/托盘**（macOS/Windows，fyne.io/systray）：显示对端数量（3 秒刷新）、
暂停/恢复本机剪贴板外发、退出。`LANCLIP_NO_TRAY=1` 关闭（服务器/CI/smoke 脚本已默认关闭）。

**其他**：

- macOS 剪贴板文件读取从弃用的 `NSFilenamesPboardType` 迁移到 `NSPasteboardTypeFileURL`
  （消除编译警告，Finder 复制→自动同步实测通过）。
- `hello_ok` 帧回带服务端身份（device/version），用于发送端判断对端是否支持 ack 协议。
- 新增测试：续传（正常+损坏前缀）、`AckProtocol` 版本判定；共 11 个测试。

## 0.2.0 (2026-10-25)

> 本版本同时合并了并行开发的两个提交（PIN 一键配对 internal/pair、复制文件自动同步
> CF_HDROP/NSFilenamesPboardType、Android 端骨架），并修复了一个严重仓库缺陷：
> `.gitignore` 的 `lanclip` 模式误吞了整个 `cmd/lanclip/` 目录，导致 0.1.0~0.1.x
> 的远端仓库缺失 CLI 入口。cmd/ 已恢复并补齐 LANCLIP_PEERS 静态对端、本地 HTTP API
> （/api/peers、/api/send-text、/api/shot）、pair-advertise/pair 一键配对命令，
> smoke.sh 全量通过。

**安全加固**（均为破坏性协议变更，0.1.x 与 0.2.0 互不相认）：

- Hello 认证改为**通道绑定**：HMAC 输入加入 TLS exporter 值，杜绝中间人用自有连接转发重放静态标签（此前标签为静态 `HMAC(key, deviceID)`）。
- 接收端文件名经 `SanitizeFileName` 消毒，封堵 manifest 路径穿越（`../../`、绝对路径、反斜杠、NUL）。
- 分块数据长度强制 ≤256KB、偏移强制顺序、总量不得超出 manifest 声明——封堵恶意块头触发的巨型内存分配（OOM DoS）。
- 剪贴板图片收发两端增加 32MB 上限（图片走内存缓冲路径；文件仍为无上限磁盘流式）。

**功能**：

- 新增 `lanclip key-export` / `key-import`，替代手工拷贝 group.key 的配对方式。
- Windows：剪贴板图片完整支持（CF_DIBV5 ↔ PNG，32bpp BI_BITFIELDS / 24bpp）；文本读取改为按 GlobalSize 限界，修复潜在越界。

**功能（合并自并行提交）**：

- 一键 PIN 配对：`lanclip pair-advertise` 显示一次性 6 位 PIN，新设备 `lanclip pair <IP>` 输码入组（AES-GCM 加密传输组密钥，5 次尝试上限）。
- 复制文件自动同步：资源管理器 CF_HDROP / Finder NSFilenamesPboardType 复制的文件自动作为文件批次推给对端。
- LANCLIP_PEERS 静态对端（mDNS 不可用的沙箱/受限网络）与本地 HTTP API（手机/快捷指令接入）。
- Android 端骨架（android/，Kotlin）。

**其他**：

- 删除未使用的 `Engine.Dial` 与"TOFU 指纹固定"（原实现只记录不校验，属虚假安全声明，已由通道绑定 HMAC 取代）。
- 新增单元/集成测试：认证绑定、路径穿越、超长块头、协议头编解码；smoke.sh 断言适配多地址场景。
- 文档修正：明确可靠性来自逐块 sha256 + 顺序偏移 + 整文件校验（非逐块 ACK）；go.mod 对齐 CI（go 1.24）；
  修复重写 serve 时引入的 TLS 双重包裹回归（smoke.sh 捕获）。

## 0.1.0 (2026-10-11)

初始版本：mDNS 发现、TLS 1.3、组密钥认证、文本/图片/文件同步、macOS 双实例实测（100MB 文件恒定内存）。
